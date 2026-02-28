"""
VulnHawk - FastAPI Server
API-powered vulnerability scanner using CrewAI + Ollama/Gemini.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000

Changes in this PR:
  1. Import BOMParentResolverTool
  2. _build_fallback_report: call BOMParentResolverTool per vulnerable dep;
     add "Via Parent" column to Upgrade Plan table;
     add "BOM Managed" column to Compatibility Analysis table;
     add "Type" column (DIRECT / TRANSITIVE depth=N) to vuln tables
  3. upgrade_task: prepend BOM Parent Resolver as Step 1
  4. report_task: add BOM column format instructions + Type column
"""

import asyncio
import os
import pathlib
import re
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import httpx
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from crewai import Crew, Process, Task

from agents import create_agents, get_llm, LLM_VENDOR, OLLAMA_URL
from tools import (
    OSVVulnerabilityCheckTool,
    DetectBuildSystemTool,
    ExtractDependenciesTool,
    MavenCentralVersionLookupTool,
    BOMParentResolverTool,          # NEW
    FetchChangelogTool,
    SearchCodeUsageTool,
)

load_dotenv()

app = FastAPI(
    title="VulnHawk",
    description="AI-powered vulnerability scanner using CrewAI",
    version="1.0.0",
)

_STATIC = pathlib.Path(__file__).parent / "static"
if _STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

    @app.get("/", response_class=FileResponse, include_in_schema=False)
    async def ui():
        return FileResponse(str(_STATIC / "index.html"))


class ScanRequest(BaseModel):
    input: str | None = None
    github_url: str | None = None


class ScanResponse(BaseModel):
    result: str


def resolve_repo_path(github_url: str) -> tuple[str, str]:
    """Clone a GitHub URL and return (repo_path, tmp_dir)."""
    if not re.match(r"https?://github\.com/", github_url) and not github_url.endswith(".git"):
        raise HTTPException(status_code=400, detail=f"Invalid GitHub URL: {github_url}")

    tmp_dir = tempfile.mkdtemp(prefix="vulnhawk_")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", github_url, tmp_dir],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(
            status_code=400,
            detail=f"git clone failed: {result.stderr.strip()}"
        )
    return tmp_dir, tmp_dir


def clean_report(text: str) -> str:
    """Strip LLM reasoning traces and stray markdown fences."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"<think>.*$", "", text, flags=re.DOTALL)
    text = text.strip()
    text = re.sub(r"^\s*```(?:markdown)?\s*\n", "", text)
    text = re.sub(r"\n\s*```\s*$", "", text)
    lines = text.splitlines()
    cleaned = []
    for line in lines:
        if line.lstrip().startswith("|"):
            line = re.sub(r" {3,}", " ", line)
        cleaned.append(line.rstrip())
    return "\n".join(cleaned)


def _extract_allowlist(report_text: str) -> list[str]:
    for line in report_text.splitlines():
        if "dependency allowlist" not in line.lower():
            continue
        match = re.search(r"Dependency Allowlist\s*:\s*(\[.*\])", line, re.IGNORECASE)
        if match:
            break
    else:
        match = None
    if not match:
        raise ValueError("Report missing 'Dependency Allowlist: [...]' line.")
    try:
        allowlist = json.loads(match.group(1))
    except Exception as exc:
        raise ValueError(f"Invalid Dependency Allowlist JSON: {exc}") from exc
    if not isinstance(allowlist, list):
        raise ValueError("Dependency Allowlist must be a JSON array.")
    return [str(x).strip() for x in allowlist if str(x).strip()]


def _extract_table_dependencies(report_text: str) -> dict[str, set[str]]:
    deps = set()
    upgrades = set()
    sections: dict[str, set[str]] = {}
    current_section = "unknown"
    vuln_ids: dict[str, set[str]] = {}
    dep_sections = (
        "critical & high vulnerabilities",
        "medium & low vulnerabilities",
        "upgrade plan",
        "compatibility analysis",
    )
    for line in report_text.splitlines():
        if line.startswith("## "):
            current_section = re.sub(r"^\d+\.\s*", "", line[3:].strip()).lower()
        if not line.lstrip().startswith("|"):
            continue
        if re.match(r"^\s*\|\s*:?-{2,}:?\s*\|", line):
            continue
        if current_section not in dep_sections:
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cols:
            continue
        dep = cols[0].strip("` *_").strip()
        if not dep or dep.lower() in ("dependency", "none", "n/a", "-"):
            continue
        deps.add(dep)
        sections.setdefault(current_section, set()).add(dep)
        vuln_ids.setdefault(current_section, set())
        if current_section == "upgrade plan":
            if len(cols) >= 2:
                upgrade = cols[1].strip("` *_").strip().replace("\u2192", "->")
                if upgrade and upgrade.lower() != "upgrade":
                    upgrades.add(upgrade)
        if current_section in ("critical & high vulnerabilities", "medium & low vulnerabilities"):
            if len(cols) >= 2:
                vuln_id = cols[1].strip("` *_").strip()
                if vuln_id and vuln_id.lower() != "vuln id":
                    vuln_ids[current_section].add(vuln_id)
    return {"dependencies": deps, "upgrades": upgrades, "sections": sections, "vuln_ids": vuln_ids}


def _resolve_deps(deps: set[str], allowlist: set[str]) -> set[str]:
    resolved = set()
    for dep in deps:
        if dep in allowlist:
            resolved.add(dep)
        elif dep.count(":") < 2:
            matches = {a for a in allowlist if a.startswith(dep + ":")}
            resolved.update(matches if matches else {dep})
        else:
            resolved.add(dep)
    return resolved


def _parse_vuln_json(vuln_json: str) -> tuple[set[str], set[str], list[dict]]:
    """Extract (allowlist, vuln_ids, vuln_summary) from pre-computed OSV JSON."""
    allowlist: set[str] = set()
    vuln_ids: set[str] = set()
    vuln_summary: list[dict] = []
    try:
        vuln_report = json.loads(vuln_json)
    except Exception:
        return allowlist, vuln_ids, vuln_summary
    if not isinstance(vuln_report, dict):
        return allowlist, vuln_ids, vuln_summary
    for item in vuln_report.get("vulnerabilities", []):
        dep   = item.get("dependency", "")
        parts = dep.split(":")
        if len(parts) >= 3:
            allowlist.add(f"{parts[0]}:{parts[1]}:{parts[2]}")
        for vid in item.get("vulnerability_ids", []) or []:
            if vid:
                vuln_ids.add(vid)
        details       = item.get("details", []) or []
        severity      = ""
        item_fixed: list[str] = []
        for det in details:
            sev = det.get("severity", "")
            if sev and sev not in ("UNKNOWN", "") and not severity:
                severity = sev
            for fv in det.get("fixed_versions", []) or []:
                if fv and fv not in item_fixed:
                    item_fixed.append(fv)
        vuln_summary.append({
            "dependency":     dep,
            "vuln_ids":       item.get("vulnerability_ids", []),
            "severity":       severity,
            "fixed_versions": item_fixed,
            "summary":        details[0].get("summary", "") if details else "",
        })
    return allowlist, vuln_ids, vuln_summary


def _parse_version_tuple(version_str: str) -> tuple:
    if not version_str:
        return ()
    parts = []
    for p in re.split(r"[-.]", re.sub(r"[^0-9.\-]", "", version_str)):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts)


def _build_fallback_report(
    scan_path: str,
    build_system: str,
    vuln_json: str,
    expected_allowlist: set[str],
    deps_json: str = "",
) -> str:
    """
    Generate a deterministic Markdown report directly from pre-computed OSV data.

    Changes vs original:
    - Calls BOMParentResolverTool for each vulnerable dep
    - Adds 'Via Parent' column to Upgrade Plan table
    - Adds 'BOM Managed' column to Compatibility Analysis table
    - Adds 'Type' column (DIRECT / TRANSITIVE depth=N) to vulnerability tables
    """
    vuln_report: dict = {}
    if vuln_json:
        try:
            vuln_report = json.loads(vuln_json)
        except Exception:
            pass

    vulns         = vuln_report.get("vulnerabilities", [])
    total_checked = vuln_report.get("total_dependencies_checked", 0)
    vuln_count    = vuln_report.get("vulnerable_count", 0)
    safe_count    = vuln_report.get("safe_count", 0)

    # Build a depth map from the full dep list so we can label DIRECT vs TRANSITIVE
    depth_map: dict[str, int] = {}   # "group_id:artifact_id:version" -> depth
    if deps_json:
        try:
            for dep_obj in json.loads(deps_json):
                key = (
                    f"{dep_obj.get('group_id','')}:"
                    f"{dep_obj.get('artifact_id','')}:"
                    f"{dep_obj.get('version','')}"
                )
                depth_map[key] = dep_obj.get("depth", 0)
        except Exception:
            pass

    def dep_type_label(dep_coord: str) -> str:
        depth = depth_map.get(dep_coord, 0)
        if depth == 0:
            return "DIRECT"
        return f"TRANSITIVE (depth={depth})"

    # ── Vulnerability rows (one per CVE ID) ───────────────────────────────────
    crit_rows: list[str] = []
    medlow_rows: list[str] = []
    for item in vulns:
        dep        = item.get("dependency", "")
        details    = item.get("details", []) or []
        detail_map = {d.get("id", ""): d for d in details}
        dep_type   = dep_type_label(dep)
        for vid in item.get("vulnerability_ids", []) or []:
            if not vid:
                continue
            det     = detail_map.get(vid, {})
            sev     = det.get("severity", "UNKNOWN") or "UNKNOWN"
            summary = det.get("summary", "Details not fetched") or "Details not fetched"
            fixed   = ", ".join(det.get("fixed_versions", []) or []) or "—"
            row     = f"| {dep} | {dep_type} | {vid} | {sev} | {summary[:200]} | {fixed} |"
            if sev in ("CRITICAL", "HIGH"):
                crit_rows.append(row)
            else:
                medlow_rows.append(row)

    # ── Upgrade + Compatibility rows (one per vulnerable dependency) ──────────
    upgrade_rows: list[str] = []
    compat_rows:  list[str] = []
    bom_tool = BOMParentResolverTool()

    for item in vulns:
        dep     = item.get("dependency", "")
        parts   = dep.split(":")
        if len(parts) < 3:
            continue
        group_id, artifact_id, current_version = parts[0], parts[1], parts[2]

        fixed_versions: list[str] = []
        for det in item.get("details", []) or []:
            fixed_versions.extend(det.get("fixed_versions", []) or [])
        fixed_versions = list(dict.fromkeys(fixed_versions))

        dep_vuln_ids: list[str] = [
            det.get("id", "") for det in (item.get("details", []) or [])
            if det.get("id", "")
        ]

        # ── Step 1: BOM parent check (NEW) ────────────────────────────────────
        # Determine the minimum safe version to pass to BOM resolver
        safe_version = ""
        if fixed_versions:
            safe_version = sorted(fixed_versions, key=_parse_version_tuple)[0]

        bom_result: dict = {}
        via_parent_label = "—"
        bom_note = ""
        if safe_version:
            try:
                bom_raw    = bom_tool._run(
                    group_id=group_id,
                    artifact_id=artifact_id,
                    safe_version=safe_version,
                )
                bom_result = json.loads(bom_raw)
            except Exception:
                bom_result = {}

        if bom_result.get("fix_via_parent"):
            parent_artifact = bom_result.get("parent_artifact", "")
            bump_to         = bom_result.get("bump_parent_to", "")
            ships_ver       = bom_result.get("parent_ships_version", "")
            # Short label for the table cell
            short_parent    = parent_artifact.split(":")[-1] if parent_artifact else "spring-boot"
            via_parent_label = f"{short_parent} → {bump_to}"
            bom_note = (
                f"BOM-managed. Bump {short_parent} to {bump_to} "
                f"(ships {artifact_id} {ships_ver})"
            )

        # ── Step 2: Maven Central version lookup ──────────────────────────────
        lookup_json = json.dumps({
            "group_id":       group_id,
            "artifact_id":    artifact_id,
            "current_version": current_version,
            "fixed_versions": fixed_versions,
        })
        try:
            lookup      = json.loads(MavenCentralVersionLookupTool()._run(lookup_json))
            target_version: str = lookup.get("recommended_upgrade") or ""
        except Exception:
            lookup, target_version = {}, ""

        # If BOM resolver found a parent-managed version, use that as target
        if bom_result.get("fix_via_parent") and bom_result.get("parent_ships_version"):
            target_version = bom_result["parent_ships_version"]

        if not target_version and fixed_versions:
            target_version = sorted(fixed_versions, key=_parse_version_tuple)[-1]
        if not target_version:
            target_version = current_version

        upgrade      = (
            f"{group_id}:{artifact_id}:{current_version} -> "
            f"{group_id}:{artifact_id}:{target_version}"
        )
        fix_version  = ", ".join(fixed_versions) or target_version or "UNKNOWN"
        vuln_id_str  = ", ".join(dep_vuln_ids[:3])
        target_parts = _parse_version_tuple(target_version)
        current_parts = _parse_version_tuple(current_version)
        same_major   = bool(target_parts and current_parts and target_parts[0] == current_parts[0])

        if target_version == current_version:
            reason = "No fix available yet; monitor for updates"
        elif bom_result.get("fix_via_parent"):
            reason = f"Upgrade via parent BOM ({via_parent_label}) fixing {vuln_id_str}"
        elif target_version in fixed_versions:
            reason = f"Patched release fixing {vuln_id_str}"
            if same_major:
                reason += "; same major version"
        else:
            reason = f"Latest safe release fixing {vuln_id_str}"
            if same_major:
                reason += "; same major version"

        upgrade_rows.append(
            f"| {dep} | {upgrade} | {via_parent_label} | {reason} | {fix_version} |"
        )

        # ── Step 3: Changelog ─────────────────────────────────────────────────
        changelog_json = json.dumps({
            "group_id":       group_id,
            "artifact_id":    artifact_id,
            "current_version": current_version,
            "target_version": target_version,
        })
        try:
            changelog    = json.loads(FetchChangelogTool()._run(changelog_json))
            breaking     = changelog.get("breaking_changes", []) or []
            breaking_text = "; ".join(breaking[:3]) if breaking else "None noted"
            safe_str      = "YES" if changelog.get("safe_to_upgrade", True) else "NO"
            confidence    = changelog.get("confidence_score", 0)
        except Exception:
            breaking_text, safe_str, confidence = "Unknown", "UNKNOWN", 0

        # ── Step 4: Code usage ────────────────────────────────────────────────
        usage_json = json.dumps({
            "repo_path":       scan_path,
            "package_pattern": group_id,
        })
        try:
            usage    = json.loads(SearchCodeUsageTool()._run(usage_json))
            affected = "YES" if usage.get("usage_found") else "NO"
        except Exception:
            affected = "UNKNOWN"

        bom_col = bom_note if bom_note else "Direct dep"

        compat_rows.append(
            f"| {dep} | {upgrade} | {bom_col} | {breaking_text} | {affected} "
            f"| {safe_str} (confidence: {confidence}%) |"
        )

    # ── All-deps overview ─────────────────────────────────────────────────────
    vuln_dep_map: dict[str, list[str]] = {
        item.get("dependency", ""): [
            v for v in (item.get("vulnerability_ids") or []) if v
        ]
        for item in vulns
        if item.get("dependency")
    }

    dep_overview_rows: list[str] = []
    all_deps_parsed: list[dict] = []
    if deps_json:
        try:
            all_deps_parsed = json.loads(deps_json)
        except Exception:
            pass

    for dep_obj in all_deps_parsed:
        g     = dep_obj.get("group_id", "")
        a     = dep_obj.get("artifact_id", "")
        v     = dep_obj.get("version", "")
        scope = dep_obj.get("scope", "compile")
        depth = dep_obj.get("depth", 0)
        if not (g and a and v):
            continue
        coord    = f"{g}:{a}:{v}"
        dep_type = "DIRECT" if depth == 0 else f"TRANSITIVE (depth={depth})"
        if coord in vuln_dep_map:
            vids_str = ", ".join(vuln_dep_map[coord][:3])
            if len(vuln_dep_map[coord]) > 3:
                vids_str += f" (+{len(vuln_dep_map[coord])-3} more)"
            status = "VULNERABLE"
        else:
            vids_str = "—"
            status   = "SAFE"
        dep_overview_rows.append(
            f"| {coord} | {dep_type} | {scope} | {status} | {vids_str} |"
        )

    allowlist    = sorted(expected_allowlist)
    report_lines = [
        "# Security Vulnerability Report",
        "",
        "## 1. Executive Summary",
        (
            f"The security scan identified **{vuln_count}** vulnerabilities "
            f"across **{total_checked}** dependencies "
            f"({sum(1 for d in all_deps_parsed if d.get('depth', 0) == 0)} direct, "
            f"{sum(1 for d in all_deps_parsed if d.get('depth', 0) > 0)} transitive)."
        ),
        "",
        "## 2. Build System",
        f"The build system used for this project is **{build_system.upper()}**.",
        "",
        "## 3. Scan Statistics",
        f"- Total Dependencies Checked: {total_checked}",
        f"- Vulnerable Count: {vuln_count}",
        f"- Safe Count: {safe_count}",
        "",
        "## 4. Critical & High Vulnerabilities",
        "| Dependency | Type | Vuln ID | Severity | Summary | Fix Version |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    report_lines.extend(crit_rows)
    report_lines.extend([
        "",
        "## 5. Medium & Low Vulnerabilities",
        "| Dependency | Type | Vuln ID | Severity | Summary | Fix Version |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    report_lines.extend(medlow_rows)
    report_lines.extend([
        "",
        "## 6. Upgrade Plan",
        "| Dependency | Upgrade | Via Parent | Reason | Fix Version |",
        "| --- | --- | --- | --- | --- |",
    ])
    report_lines.extend(upgrade_rows)
    report_lines.extend([
        "",
        "## 7. Compatibility Analysis",
        "| Dependency | Upgrade | BOM Managed | Breaking Changes | Project Affected | Safe to Upgrade |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    report_lines.extend(compat_rows)
    report_lines.extend([
        "",
        "## 8. Compatibility Warnings",
        "None noted." if not compat_rows else (
            "Review BOM-managed dependencies — bump the parent version, "
            "not the library directly. Review breaking changes before upgrading."
        ),
        "",
        "## 9. Next Steps",
        "- Apply recommended upgrades and run the full test suite.",
        "- For BOM-managed deps (e.g. Tomcat via Spring Boot): bump the parent version.",
        "- Review breaking changes and update configuration as needed.",
    ])

    if dep_overview_rows:
        report_lines.extend([
            "",
            "## 10. All Dependencies",
            "| Dependency | Type | Scope | Status | Vulnerabilities |",
            "| --- | --- | --- | --- | --- |",
        ])
        report_lines.extend(dep_overview_rows)

    report_lines.extend([
        "",
        f"Dependency Allowlist: {json.dumps(allowlist)}",
    ])

    return "\n".join(report_lines)


def _compute_vuln_expectations(repo_path: str) -> tuple[str, set[str], set[str]]:
    build_system = DetectBuildSystemTool()._run(repo_path)
    if build_system.startswith("ERROR") or build_system == "unknown":
        raise ValueError(f"Failed to detect build system: {build_system}")

    deps_json = ExtractDependenciesTool()._run(repo_path, build_system)
    try:
        deps = json.loads(deps_json)
    except Exception:
        return build_system, set(), set()
    if not isinstance(deps, list) or not deps:
        return build_system, set(), set()

    vuln_json = OSVVulnerabilityCheckTool()._run(json.dumps(deps))
    try:
        vuln_report = json.loads(vuln_json)
    except Exception:
        return build_system, set(), set()
    if not isinstance(vuln_report, dict):
        return build_system, set(), set()

    allowlist: set[str] = set()
    vuln_ids: set[str]  = set()
    for item in vuln_report.get("vulnerabilities", []):
        dep   = item.get("dependency", "")
        parts = dep.split(":")
        if len(parts) >= 3:
            allowlist.add(f"{parts[0]}:{parts[1]}:{parts[2]}")
        for vid in item.get("vulnerability_ids", []) or []:
            if vid:
                vuln_ids.add(vid)

    return build_system, allowlist, vuln_ids


def validate_report_dependencies(
    report_text: str,
    expected_build_system: str,
    expected_allowlist: set[str],
    expected_vuln_ids: set[str],
    strict_upgrade_coverage: bool = True,
) -> None:
    build_match = re.search(
        r"## (?:\d+\.\s*)?Build System\s*\n([^\n]+)", report_text, re.IGNORECASE
    )
    if build_match:
        build_line = build_match.group(1).strip().lower()
        report_system = (
            "maven" if "maven" in build_line
            else "gradle" if "gradle" in build_line
            else ""
        )
    else:
        report_system = ""

    if expected_build_system and report_system and expected_build_system != report_system:
        raise ValueError(
            f"Build System mismatch. Expected '{expected_build_system}', got '{report_system}'."
        )

    if "dependency allowlist" not in report_text.lower():
        allowlist = set(expected_allowlist)
    else:
        try:
            allowlist = set(_extract_allowlist(report_text))
        except ValueError:
            allowlist = set(expected_allowlist)

    invalid_allow = sorted(d for d in allowlist if d.count(":") < 2)
    if invalid_allow:
        raise ValueError(
            "Dependency Allowlist entries must be group:artifact:version. "
            "Invalid: " + ", ".join(invalid_allow)
        )

    if not expected_allowlist:
        if allowlist:
            raise ValueError("Dependency Allowlist must be empty when no vulnerabilities are found.")
    elif allowlist != expected_allowlist:
        missing = sorted(d for d in expected_allowlist if d not in allowlist)
        extra   = sorted(d for d in allowlist if d not in expected_allowlist)
        raise ValueError(
            "Dependency Allowlist mismatch. "
            f"Missing: {', '.join(missing) if missing else 'none'}. "
            f"Extra: {', '.join(extra) if extra else 'none'}."
        )

    extracted = _extract_table_dependencies(report_text)
    mentioned = _resolve_deps(extracted["dependencies"], allowlist)

    invalid_mentions = sorted(d for d in mentioned if d.count(":") < 2)
    if invalid_mentions:
        raise ValueError(
            "Table Dependency entries must be group:artifact:version. "
            "Invalid: " + ", ".join(invalid_mentions)
        )

    extra = sorted(d for d in mentioned if d not in allowlist)
    if extra:
        raise ValueError("Report mentions dependencies not in allowlist: " + ", ".join(extra))

    bad_upgrades = []
    for up in extracted["upgrades"]:
        parts = [p.strip() for p in up.split("->")]
        if len(parts) != 2:
            bad_upgrades.append(up)
            continue
        if parts[0].count(":") < 2 or parts[1].count(":") < 2:
            bad_upgrades.append(up)
    if bad_upgrades:
        raise ValueError(
            "Upgrade entries must be '<group:artifact:version> -> <group:artifact:version>'. "
            "Invalid: " + ", ".join(sorted(bad_upgrades))
        )

    sections     = extracted["sections"]
    upgrade_deps = _resolve_deps(sections.get("upgrade plan", set()), allowlist)
    compat_deps  = _resolve_deps(sections.get("compatibility analysis", set()), allowlist)

    if strict_upgrade_coverage:
        if not expected_allowlist:
            if upgrade_deps:
                raise ValueError("Upgrade Plan must be empty when no vulnerabilities are found.")
            if compat_deps:
                raise ValueError("Compatibility Analysis must be empty when no vulnerabilities are found.")
        else:
            missing_upgrade = sorted(d for d in allowlist if d not in upgrade_deps)
            tolerance = max(2, round(len(allowlist) * 0.15))
            if len(missing_upgrade) > tolerance:
                raise ValueError("Upgrade Plan missing dependencies: " + ", ".join(missing_upgrade))

            missing_compat = sorted(d for d in allowlist if d not in compat_deps)
            if missing_compat:
                raise ValueError(
                    "Compatibility Analysis missing dependencies: " + ", ".join(missing_compat)
                )

    vuln_ids_extracted = extracted["vuln_ids"]
    crit_ids   = vuln_ids_extracted.get("critical & high vulnerabilities", set())
    medlow_ids = vuln_ids_extracted.get("medium & low vulnerabilities", set())
    reported_ids = set().union(crit_ids, medlow_ids)

    dup_ids = sorted(crit_ids.intersection(medlow_ids))
    if dup_ids:
        raise ValueError(
            "Vulnerability IDs duplicated across Critical & High and Medium & Low tables: "
            + ", ".join(dup_ids)
        )

    missing_ids = sorted(v for v in expected_vuln_ids if v not in reported_ids)
    if missing_ids:
        raise ValueError("Vulnerability tables missing IDs: " + ", ".join(missing_ids))

    extra_ids = sorted(v for v in reported_ids if v not in expected_vuln_ids)
    if extra_ids:
        raise ValueError("Vulnerability tables include unknown IDs: " + ", ".join(extra_ids))


def create_tasks(
    repo_scanner, vuln_analyst, upgrade_strategist, report_generator,
    repo_path: str,
    build_system: str = "",
    deps_json: str = "",
    vuln_summary: list | None = None,
):
    """Create the full 5-task pipeline for repo scanning."""
    n_deps = 0
    if deps_json:
        try:
            n_deps = len(json.loads(deps_json))
        except Exception:
            pass

    vuln_summary = vuln_summary or []
    n_vulns      = len(vuln_summary)

    if vuln_summary:
        vuln_checklist = "\n".join(
            f"- {v['dependency']}  severity={v['severity']}  "
            f"vuln_ids={v['vuln_ids'][:3]}{'...' if len(v['vuln_ids']) > 3 else ''}  "
            f"fixed_versions={v['fixed_versions']}"
            for v in vuln_summary
        )
        dep_names_list = "\n".join(f"- {v['dependency']}" for v in vuln_summary)
    else:
        vuln_checklist = "(none)"
        dep_names_list = "(none)"

    # ── Task 1: Build detection ───────────────────────────────────────────────
    if build_system:
        build_task = Task(
            description=(
                f"The build system for the repository at {repo_path} has already been "
                f"detected as: **{build_system}**.\n\nConfirm this result and return it."
            ),
            expected_output=f'The detected build system: "{build_system}"',
            agent=repo_scanner,
        )
    else:
        build_task = Task(
            description=(
                f"Use the 'Detect Build System' tool on the repository at: {repo_path}\n\n"
                "Return only the detected build system name ('maven' or 'gradle')."
            ),
            expected_output="The detected build system: 'maven' or 'gradle'.",
            agent=repo_scanner,
        )

    # ── Task 2: Dependency extraction ────────────────────────────────────────
    if deps_json and n_deps > 0:
        dep_task = Task(
            description=(
                f"The complete dependency tree for the {build_system} project at {repo_path} "
                f"has already been extracted ({n_deps} dependencies, including transitive).\n\n"
                f"Full dependency list:\n\n{deps_json}\n\n"
                "Return this exact JSON array as your output. Do NOT modify it."
            ),
            expected_output=(
                f"The complete JSON array of {n_deps} dependencies. "
                "Each object has: group_id, artifact_id, version, scope, depth."
            ),
            agent=repo_scanner,
            context=[build_task],
        )
    else:
        dep_task = Task(
            description=(
                f"Use the 'Extract Dependencies' tool to get ALL dependencies "
                f"(including transitive) for the repository at: {repo_path}\n\n"
                f"The build system is: {build_system or 'from the previous task'}\n\n"
                "Return the complete JSON array from the tool."
            ),
            expected_output=(
                "The complete JSON array of dependencies. "
                "Each object has: group_id, artifact_id, version, scope, depth."
            ),
            agent=repo_scanner,
            context=[build_task],
        )

    # ── Task 3: Vulnerability check ──────────────────────────────────────────
    vuln_task = Task(
        description=(
            "Check ALL dependencies from the previous task against the OSV vulnerability database.\n\n"
            "Steps:\n"
            "1. Take the COMPLETE JSON array from the previous task output.\n"
            "2. Pass that ENTIRE array as-is to the 'Check OSV Vulnerabilities' tool.\n"
            "3. Return the tool's full JSON result as-is.\n\n"
            "IMPORTANT: The tool expects a JSON ARRAY. Pass ALL dependencies in a single call.\n\n"
            "CRITICAL: After getting results, COUNT the vulnerable dependencies. "
            "The vulnerable_count MUST match the vulnerabilities array length. "
            "Do NOT drop or omit any — especially CRITICAL ones like Log4Shell (log4j)."
        ),
        expected_output=(
            "The full JSON vulnerability report with ALL entries preserved:\n"
            "- total_dependencies_checked, vulnerable_count, safe_count\n"
            "- vulnerabilities array with ALL dependency coordinates, IDs, severity, summaries, "
            "and fixed versions."
        ),
        agent=vuln_analyst,
        context=[dep_task],
    )

    # ── Task 4: Upgrade strategy (BOM-first) ─────────────────────────────────
    upgrade_task = Task(
        description=(
            f"You MUST produce upgrade recommendations for ALL {n_vulns} vulnerable dependencies "
            "listed below. Do NOT skip any entry.\n\n"
            f"COMPLETE LIST OF VULNERABLE DEPENDENCIES ({n_vulns} total):\n"
            f"{vuln_checklist}\n\n"
            "CRITICAL RULES:\n"
            "- ALWAYS recommend an UPGRADE (newer version). NEVER recommend a downgrade.\n"
            "- ALWAYS check BOM management FIRST before anything else.\n\n"
            "Steps for EACH vulnerable dependency:\n\n"
            "STEP 1 — BOM CHECK (do this first, every time):\n"
            "  Use the 'BOM Parent Resolver' tool:\n"
            '    group_id: "...", artifact_id: "...", safe_version: "<minimum_fix_version>"\n'
            "  If fix_via_parent is true: recommend bumping the PARENT, not the dep directly.\n"
            "  If fix_via_parent is false: proceed to step 2.\n\n"
            "STEP 2 — VERSION LOOKUP:\n"
            "  Use 'Lookup Latest Safe Version':\n"
            '    group_id: "...", artifact_id: "...", current_version: "...", fixed_versions: ["..."]\n\n'
            "STEP 3 — CHANGELOG:\n"
            "  Use 'Fetch Changelog':\n"
            '    group_id: "...", artifact_id: "...", current_version: "...", target_version: "..."\n\n'
            "STEP 4 — CODE USAGE:\n"
            "  Use 'Search Code Usage':\n"
            f'    repo_path: "{repo_path}", package_pattern: "<package.name>"\n\n'
            "STEP 5 — DOCS (only if changelog shows breaking changes):\n"
            "  Use 'Read Project Docs':\n"
            f'    repo_path: "{repo_path}", search_terms: ["<affected_feature>"]\n\n'
            "Output: JSON array with per-dependency fields including bom_managed, "
            "via_parent_version, confidence_score."
        ),
        expected_output=(
            "A JSON array of upgrade recommendations with: dependency, current_version, "
            "recommended_version, bom_managed (bool), via_parent_version, risk_level, "
            "compatibility_notes, code_usage, affected_files, vulnerabilities_fixed, "
            "changelog_summary, breaking_changes, safe_to_upgrade (bool), "
            "confidence_score (0-100), migration_steps."
        ),
        agent=upgrade_strategist,
        context=[dep_task, vuln_task],
    )

    # ── Task 5: Report ────────────────────────────────────────────────────────
    report_task = Task(
        description=(
            "Generate a comprehensive security vulnerability report in Markdown.\n\n"
            f"Build System: {build_system or 'see previous task'}\n\n"
            "Your ONLY job is to write a Markdown security report based on the vulnerability "
            "and upgrade data from the previous tasks. Do NOT output JSON.\n\n"
            f"MANDATORY: Your Upgrade Plan and Compatibility Analysis tables MUST contain "
            f"exactly {n_vulns} data rows — one for each vulnerable dependency below:\n"
            f"{dep_names_list}\n\n"
            "CRITICAL: ONLY include dependencies that appear in the vulnerability data.\n\n"
            "REQUIRED SECTIONS:\n"
            "1. Executive Summary — mention total vulns, direct vs transitive breakdown\n"
            "2. Build System\n"
            "3. Scan Statistics — exact counts\n"
            "4. Critical & High Vulnerabilities (table)\n"
            "5. Medium & Low Vulnerabilities (table)\n"
            "6. Upgrade Plan — one row per vulnerable dependency\n"
            "7. Compatibility Analysis\n"
            "8. Compatibility Warnings\n"
            "9. Next Steps\n"
            "10. Dependency Allowlist — single line:\n"
            '    Dependency Allowlist: ["group:artifact:version", ...]\n\n'
            "CRITICAL FORMAT RULES:\n"
            "- Dependency column: always 'group_id:artifact_id:version'\n"
            "- Allowlist MUST exactly match vulnerability data dependencies\n\n"
            "TABLE FORMAT for vulnerabilities:\n"
            "| Dependency | Type | Vuln ID | Severity | Summary | Fix Version |\n"
            "| --- | --- | --- | --- | --- | --- |\n"
            "Type column: 'DIRECT' or 'TRANSITIVE (depth=N)'\n\n"
            "TABLE FORMAT for Upgrade Plan:\n"
            "| Dependency | Upgrade | Via Parent | Reason | Fix Version |\n"
            "| --- | --- | --- | --- | --- |\n"
            "Via Parent column: if BOM-managed, show 'spring-boot → X.Y.Z'; else '—'\n"
            "Upgrade column: Use ASCII '->' (hyphen + greater-than, NOT Unicode '→'): "
            "'<group:artifact:version> -> <group:artifact:version>'. "
            "ALWAYS include the full group and artifact on BOTH sides — "
            "NEVER write abbreviated versions like '1.5.21 -> 1.5.25'. "
            "Example: 'org.assertj:assertj-core:3.27.6 -> org.assertj:assertj-core:3.27.7'. "
            "When no fix is available, repeat the current version on both sides. "
            "NEVER use 'N/A' or any non-version placeholder in the Upgrade column.\n\n"
            "TABLE FORMAT for Compatibility Analysis:\n"
            "| Dependency | Upgrade | BOM Managed | Breaking Changes | Project Affected | Safe to Upgrade |\n"
            "| --- | --- | --- | --- | --- | --- |\n"
            "BOM Managed column: 'BOM-managed. Bump spring-boot to X.Y.Z' or 'Direct dep'\n\n"
            "VERIFICATION: Count your table rows. If any dependency is missing, ADD IT."
        ),
        expected_output=(
            "A complete Markdown security report with all 9 sections. "
            "Every vulnerability must appear in the tables. "
            "Upgrade Plan must show Via Parent for BOM-managed deps. "
            "Do NOT wrap output in code fences."
        ),
        agent=report_generator,
        context=[vuln_task, upgrade_task],
    )

    return [build_task, dep_task, vuln_task, upgrade_task, report_task]


def _run_full_scan(scan_path: str) -> str:
    """Synchronous full-repo scan — runs in a thread via asyncio.to_thread."""
    # ── Step 1: Pre-compute ───────────────────────────────────────────────────
    build_system = DetectBuildSystemTool()._run(scan_path)
    if build_system.startswith("ERROR") or build_system == "unknown":
        raise ValueError(f"Failed to detect build system: {build_system}")

    deps_json = ExtractDependenciesTool()._run(scan_path, build_system)
    try:
        json.loads(deps_json)
    except Exception:
        deps_json = ""

    vuln_json = ""
    expected_allowlist: set[str] = set()
    expected_vuln_ids: set[str]  = set()
    vuln_summary: list[dict]     = []
    if deps_json:
        raw_vuln = OSVVulnerabilityCheckTool()._run(deps_json)
        try:
            json.loads(raw_vuln)
            vuln_json = raw_vuln
            expected_allowlist, expected_vuln_ids, vuln_summary = _parse_vuln_json(vuln_json)
        except Exception:
            pass

    # ── Step 2: Fast mode decision ────────────────────────────────────────────
    fast_mode = (
        os.getenv("VULNHAWK_FAST", "").lower() in ("1", "true", "yes")
        or LLM_VENDOR == "ollama"
    )

    if not fast_mode:
        # ── LLM pipeline (Gemini / cloud models) ─────────────────────────────
        repo_scanner, vuln_analyst, upgrade_strategist, report_generator = create_agents()
        tasks = create_tasks(
            repo_scanner, vuln_analyst, upgrade_strategist, report_generator,
            scan_path,
            build_system=build_system,
            deps_json=deps_json,
            vuln_summary=vuln_summary,
        )
        crew = Crew(
            agents=[repo_scanner, vuln_analyst, upgrade_strategist, report_generator],
            tasks=tasks,
            process=Process.sequential,
            verbose=True,
        )
        result      = crew.kickoff()
        report_text = clean_report(str(result))
        try:
            validate_report_dependencies(
                report_text,
                build_system,
                expected_allowlist,
                expected_vuln_ids,
            )
            return report_text
        except ValueError as llm_err:
            print(
                f"[VulnHawk] LLM report failed validation ({llm_err}). "
                "Falling back to deterministic report."
            )
    else:
        print(f"[VulnHawk] Fast mode active (LLM_VENDOR={LLM_VENDOR}). Skipping LLM pipeline.")

    # ── Step 3: Deterministic fallback (always used for Ollama) ──────────────
    fallback_text = _build_fallback_report(
        scan_path, build_system, vuln_json, expected_allowlist, deps_json
    )
    validate_report_dependencies(
        fallback_text,
        build_system,
        expected_allowlist,
        expected_vuln_ids,
        strict_upgrade_coverage=False,
    )
    return fallback_text


def _expand_maven_deps(coords: list[dict]) -> list[dict]:
    """Fully resolve all transitive Maven dependencies via recursive POM fetching."""
    MAX_DEPS    = 10_000
    SKIP_SCOPES = {"test", "provided", "system"}
    pom_cache: dict[str, dict] = {}

    def pom_url(g: str, a: str, v: str) -> str:
        return f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom"

    def fetch_pom(g: str, a: str, v: str) -> dict:
        key = f"{g}:{a}:{v}"
        if key in pom_cache:
            return pom_cache[key]
        pom_cache[key] = {}
        try:
            resp = httpx.get(pom_url(g, a, v), timeout=15, follow_redirects=True)
            if resp.status_code != 200:
                return {}
            root = ET.fromstring(resp.text)
        except Exception:
            return {}

        m  = re.match(r"\{(.+?)\}", root.tag)
        ns = f"{{{m.group(1)}}}" if m else ""

        def txt(elem, tag: str, default: str = "") -> str:
            return (elem.findtext(f"{ns}{tag}", default) or default).strip()

        parent_props: dict[str, str]    = {}
        parent_dep_mgmt: dict[str, str] = {}
        parent_elem = root.find(f"{ns}parent")
        if parent_elem is not None:
            pg = txt(parent_elem, "groupId")
            pa = txt(parent_elem, "artifactId")
            pv = txt(parent_elem, "version")
            if pg and pa and pv and not pv.startswith("${"):
                pd = fetch_pom(pg, pa, pv)
                parent_props    = pd.get("props", {})
                parent_dep_mgmt = pd.get("dep_mgmt", {})

        props: dict[str, str] = {
            "project.version": v,
            "project.groupId": g,
            "project.artifactId": a,
            **parent_props,
        }
        props_elem = root.find(f"{ns}properties")
        if props_elem is not None:
            for p in props_elem:
                props[p.tag.replace(ns, "")] = (p.text or "").strip()

        def resolve(val: str) -> str:
            for _ in range(3):
                if not val.startswith("${"):
                    break
                val = props.get(val[2:-1], val)
            return val

        dep_mgmt: dict[str, str] = dict(parent_dep_mgmt)
        dm_elem = root.find(f"{ns}dependencyManagement/{ns}dependencies")
        if dm_elem is not None:
            for d in dm_elem.findall(f"{ns}dependency"):
                dg = resolve(txt(d, "groupId"))
                da = resolve(txt(d, "artifactId"))
                dv = resolve(txt(d, "version"))
                ds = txt(d, "scope", "compile")
                if ds == "import" and dg and da and dv and not dv.startswith("${"):
                    bom = fetch_pom(dg, da, dv)
                    for k, bv in bom.get("dep_mgmt", {}).items():
                        dep_mgmt.setdefault(k, bv)
                elif dg and da and dv and not dv.startswith("${"):
                    dep_mgmt[f"{dg}:{da}"] = dv

        direct: list[dict] = []
        deps_elem = root.find(f"{ns}dependencies")
        if deps_elem is not None:
            for d in deps_elem.findall(f"{ns}dependency"):
                dg  = resolve(txt(d, "groupId"))
                da  = resolve(txt(d, "artifactId"))
                dv  = resolve(txt(d, "version"))
                ds  = txt(d, "scope", "compile")
                opt = txt(d, "optional", "false").lower()
                if ds in SKIP_SCOPES or opt == "true":
                    continue
                if not dv or dv.startswith("${"):
                    dv = dep_mgmt.get(f"{dg}:{da}", "")
                if dg and da and dv and not dv.startswith("${"):
                    direct.append({
                        "group_id": dg, "artifact_id": da,
                        "version": dv, "scope": ds,
                    })

        result = {"props": props, "dep_mgmt": dep_mgmt, "direct": direct}
        pom_cache[key] = result
        return result

    seen: dict[str, str]  = {}
    resolved: list[dict]  = []
    queue: list[dict]     = list(coords)

    while queue and len(resolved) < MAX_DEPS:
        dep = queue.pop(0)
        g   = dep.get("group_id", "").strip()
        a   = dep.get("artifact_id", "").strip()
        v   = dep.get("version", "").strip()
        if not g or not a or not v or v == "UNKNOWN":
            continue
        ga_key = f"{g}:{a}"
        if ga_key in seen:
            continue
        seen[ga_key] = v
        resolved.append(dep)
        pom_data = fetch_pom(g, a, v)
        for child in pom_data.get("direct", []):
            if f"{child['group_id']}:{child['artifact_id']}" not in seen:
                queue.append(child)

    return resolved


def _run_dep_scan(dep_input: str) -> str:
    """Synchronous dependency-list scan — runs in a thread via asyncio.to_thread."""
    from crewai import Agent

    llm = get_llm()

    recon_agent = Agent(
        role="Dependency Recon Specialist",
        goal="Parse and identify all dependencies with their exact versions",
        backstory="You parse package names, versions, and ecosystems for vulnerability analysis.",
        llm=llm,
        verbose=True,
    )
    vuln_agent = Agent(
        role="Vulnerability Hunter",
        goal="Find known CVEs and security issues in dependencies",
        backstory="You cross-reference packages against the OSV database for known exploits.",
        tools=[OSVVulnerabilityCheckTool()],
        llm=llm,
        verbose=True,
    )
    report_agent = Agent(
        role="Security Report Analyst",
        goal="Compile a clear vulnerability report with severity ratings",
        backstory="You translate raw vulnerability data into actionable reports.",
        llm=llm,
        verbose=True,
    )

    parsed_coords: list[dict] = []
    for line in dep_input.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            parsed_coords.append({
                "group_id":    parts[0].strip(),
                "artifact_id": parts[1].strip(),
                "version":     parts[2].strip(),
                "scope":       "compile",
            })

    if parsed_coords:
        expanded_coords = _expand_maven_deps(parsed_coords)
        expanded_json   = json.dumps(expanded_coords, indent=2)
        recon_desc = (
            f"Validate and confirm this pre-expanded dependency list "
            f"(direct inputs + their Maven transitive dependencies). "
            f"Return it as-is as a JSON array:\n\n{expanded_json}"
        )
    else:
        recon_desc = (
            f"Parse this dependency list into JSON with group_id, artifact_id, version:\n\n{dep_input}"
        )

    recon_task = Task(
        description=recon_desc,
        expected_output="A JSON array of packages with group_id, artifact_id, and version.",
        agent=recon_agent,
    )
    vuln_task = Task(
        description=(
            "Use the 'Check OSV Vulnerabilities' tool with the full JSON array from the previous step. "
            "Pass ALL entries — including transitive dependencies."
        ),
        expected_output="Raw CVE findings for each dependency.",
        agent=vuln_agent,
    )
    report_task = Task(
        description=(
            "Compile findings into a report with severity, CVE ID, description, and fix. "
            "For each vulnerable dependency, note whether it is BOM-managed "
            "(e.g. Tomcat is managed by Spring Boot BOM) and what parent version to bump."
        ),
        expected_output=(
            "A structured vulnerability report with severity ratings, remediation steps, "
            "and BOM parent upgrade recommendations where applicable."
        ),
        agent=report_agent,
    )

    crew = Crew(
        agents=[recon_agent, vuln_agent, report_agent],
        tasks=[recon_task, vuln_task, report_task],
        process=Process.sequential,
        verbose=True,
    )
    return str(crew.kickoff())


@app.post("/scan", response_model=ScanResponse)
async def scan(payload: ScanRequest):
    """Run a vulnerability scan on a GitHub URL or dependency list."""
    has_input = payload.input and payload.input.strip()
    has_url   = payload.github_url and payload.github_url.strip()

    if not has_input and not has_url:
        raise HTTPException(
            status_code=400,
            detail="Provide 'github_url' (full repo scan) or 'input' (dependency coordinates).",
        )

    if has_url:
        scan_path, tmp_dir = resolve_repo_path(payload.github_url)
        try:
            try:
                report_text = await asyncio.to_thread(_run_full_scan, scan_path)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            return ScanResponse(result=report_text)
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    result = await asyncio.to_thread(_run_dep_scan, payload.input)
    return ScanResponse(result=result)


@app.get("/health")
async def health():
    """Check API and LLM backend connectivity."""
    result: dict = {"status": "ok", "llm_vendor": LLM_VENDOR}

    if LLM_VENDOR == "google":
        google_key   = bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
        result["google"] = {"api_key_set": google_key}
    else:
        ollama_ok = False
        models    = []
        try:
            resp = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            resp.raise_for_status()
            models    = [m["name"] for m in resp.json().get("models", [])]
            ollama_ok = True
        except Exception:
            pass
        result["ollama"] = {"reachable": ollama_ok, "url": OLLAMA_URL, "models": models}

    return result