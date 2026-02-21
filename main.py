#!/usr/bin/env python3
"""
VulnHawk - AI Vulnerability Scanner (CLI Mode)
===============================================
Scans a Java/Kotlin repository for dependency vulnerabilities using:
- CrewAI for multi-agent orchestration
- Ollama (LLaMA 3.1) on remote Linux GPU
- OSV API for vulnerability data
- Maven Central for version lookups

Usage:
    python main.py /path/to/your/java/repo
    python main.py https://github.com/user/some-java-project

API mode:
    cd app && uvicorn main:app --host 0.0.0.0 --port 8000
"""

import sys
import os
import re
import json
import shutil
import subprocess
import tempfile
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Add app/ to path so we can import from there
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "app"))

from crewai import Crew, Process, Task
from agents import create_agents
from tools import (
    DetectBuildSystemTool,
    ExtractDependenciesTool,
    OSVVulnerabilityCheckTool,
    MavenCentralVersionLookupTool,
    FetchChangelogTool,
    SearchCodeUsageTool,
)


def clean_report(text: str) -> str:
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
    sections = {}
    current_section = "unknown"
    vuln_ids = {}
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
        # Skip separator rows like | --- |, | :--- |, | ---: |, | :---: |
        if re.match(r"^\s*\|\s*:?-{2,}:?\s*\|", line):
            continue
        if current_section not in dep_sections:
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cols:
            continue
        dep = cols[0].strip("` ").strip()
        if not dep or dep.lower() in ("dependency", "none", "n/a", "-"):
            continue
        deps.add(dep)
        if current_section not in sections:
            sections[current_section] = set()
        sections[current_section].add(dep)
        if current_section not in vuln_ids:
            vuln_ids[current_section] = set()
        # capture Upgrade column (2nd col) only for the Upgrade Plan section
        if current_section == "upgrade plan":
            if len(cols) >= 2:
                upgrade = cols[1].strip("` ").strip()
                if upgrade and upgrade.lower() != "upgrade":
                    upgrades.add(upgrade)
        # capture Vuln ID column (2nd col) for vuln tables
        if current_section in ("critical & high vulnerabilities", "medium & low vulnerabilities"):
            if len(cols) >= 2:
                vuln_id = cols[1].strip("` ").strip()
                if vuln_id and vuln_id.lower() != "vuln id":
                    vuln_ids[current_section].add(vuln_id)
    return {"dependencies": deps, "upgrades": upgrades, "sections": sections, "vuln_ids": vuln_ids}


def _resolve_deps(deps: set[str], allowlist: set[str]) -> set[str]:
    """Resolve abbreviated deps (group:artifact) to full allowlist entries (group:artifact:version)."""
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


def _compute_vuln_expectations(repo_path: str) -> tuple[str, set[str], set[str]]:
    build_system = DetectBuildSystemTool()._run(repo_path)
    if build_system.startswith("ERROR") or build_system == "unknown":
        raise ValueError(f"Failed to detect build system: {build_system}")

    deps_json = ExtractDependenciesTool()._run(repo_path, build_system)
    try:
        deps = json.loads(deps_json)
    except Exception as exc:
        raise ValueError(f"Failed to parse dependencies: {exc}") from exc
    if not isinstance(deps, list):
        raise ValueError(f"Dependency extraction failed: {deps_json}")

    vuln_json = OSVVulnerabilityCheckTool()._run(json.dumps(deps))
    try:
        vuln_report = json.loads(vuln_json)
    except Exception as exc:
        raise ValueError(f"Failed to parse OSV report: {exc}") from exc
    if not isinstance(vuln_report, dict):
        raise ValueError(f"OSV report invalid: {vuln_json}")

    allowlist = set()
    vuln_ids = set()
    for item in vuln_report.get("vulnerabilities", []):
        dep = item.get("dependency", "")
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
    build_match = re.search(r"## (?:\d+\.\s*)?Build System\s*\n([^\n]+)", report_text, re.IGNORECASE)
    if build_match:
        build_line = build_match.group(1).strip().lower()
        if "maven" in build_line:
            report_system = "maven"
        elif "gradle" in build_line:
            report_system = "gradle"
        else:
            report_system = ""
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
            raise ValueError(
                "Dependency Allowlist must be empty when no vulnerabilities are found."
            )
    elif allowlist != expected_allowlist:
        missing = sorted(d for d in expected_allowlist if d not in allowlist)
        extra = sorted(d for d in allowlist if d not in expected_allowlist)
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
        raise ValueError(
            "Report mentions dependencies not in allowlist: " + ", ".join(extra)
        )

    # Validate Upgrade column format when present
    bad_upgrades = []
    for up in extracted["upgrades"]:
        # Expected: "<group:artifact:version> -> <group:artifact:version>"
        parts = [p.strip() for p in up.split("->")]
        if len(parts) != 2:
            bad_upgrades.append(up)
            continue
        left, right = parts
        if left.count(":") < 2 or right.count(":") < 2:
            bad_upgrades.append(up)
    if bad_upgrades:
        raise ValueError(
            "Upgrade entries must be '<group:artifact:version> -> <group:artifact:version>'. "
            "Invalid: " + ", ".join(sorted(bad_upgrades))
        )

    # Ensure all allowlist deps appear in Upgrade Plan and Compatibility Analysis sections
    sections = extracted["sections"]
    upgrade_deps = _resolve_deps(sections.get("upgrade plan", set()), allowlist)
    compat_deps = _resolve_deps(sections.get("compatibility analysis", set()), allowlist)

    if strict_upgrade_coverage:
        if not expected_allowlist:
            if upgrade_deps:
                raise ValueError(
                    "Upgrade Plan must be empty when no vulnerabilities are found."
                )
            if compat_deps:
                raise ValueError(
                    "Compatibility Analysis must be empty when no vulnerabilities are found."
                )
        else:
            missing_upgrade = sorted(d for d in allowlist if d not in upgrade_deps)
            if missing_upgrade:
                raise ValueError(
                    "Upgrade Plan missing dependencies: " + ", ".join(missing_upgrade)
                )

            missing_compat = sorted(d for d in allowlist if d not in compat_deps)
            if missing_compat:
                raise ValueError(
                    "Compatibility Analysis missing dependencies: " + ", ".join(missing_compat)
                )

    # Ensure vuln tables include all vuln IDs from OSV and no extras
    vuln_ids = extracted["vuln_ids"]
    crit_ids = vuln_ids.get("critical & high vulnerabilities", set())
    medlow_ids = vuln_ids.get("medium & low vulnerabilities", set())
    reported_ids = set().union(crit_ids, medlow_ids)
    dup_ids = sorted(crit_ids.intersection(medlow_ids))
    if dup_ids:
        raise ValueError(
            "Vulnerability IDs duplicated across Critical & High and Medium & Low tables: "
            + ", ".join(dup_ids)
        )

    missing_ids = sorted(v for v in expected_vuln_ids if v not in reported_ids)
    if missing_ids:
        raise ValueError(
            "Vulnerability tables missing IDs: " + ", ".join(missing_ids)
        )

    extra_ids = sorted(v for v in reported_ids if v not in expected_vuln_ids)
    if extra_ids:
        raise ValueError(
            "Vulnerability tables include unknown IDs: " + ", ".join(extra_ids)
        )


def _parse_version_tuple(version_str: str) -> tuple:
    if not version_str:
        return ()
    clean = re.split(r"[-.]", re.sub(r"[^0-9.\-]", "", version_str))
    parts = []
    for p in clean:
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts)


def _build_fallback_report(repo_path: str) -> str:
    build_system, expected_allowlist, expected_vuln_ids = _compute_vuln_expectations(repo_path)

    deps_json = ExtractDependenciesTool()._run(repo_path, build_system)
    deps = json.loads(deps_json) if deps_json and deps_json.strip().startswith("[") else []

    vuln_json = OSVVulnerabilityCheckTool()._run(json.dumps(deps))
    vuln_report = json.loads(vuln_json) if vuln_json and vuln_json.strip().startswith("{") else {}

    vulns = vuln_report.get("vulnerabilities", [])
    total_checked = vuln_report.get("total_dependencies_checked", 0)
    vuln_count = vuln_report.get("vulnerable_count", 0)
    safe_count = vuln_report.get("safe_count", 0)

    # Build vuln rows
    crit_rows = []
    medlow_rows = []
    for item in vulns:
        dep = item.get("dependency", "")
        details = item.get("details", []) or []
        for det in details:
            vid = det.get("id", "UNKNOWN")
            sev = det.get("severity", "UNKNOWN")
            summary = det.get("summary", "No summary available")
            fixed = ", ".join(det.get("fixed_versions", []) or []) or "UNKNOWN"
            row = f"| {dep} | {vid} | {sev} | {summary} | {fixed} |"
            if sev in ("CRITICAL", "HIGH"):
                crit_rows.append(row)
            else:
                medlow_rows.append(row)

    # Build upgrade/compat rows
    upgrade_rows = []
    compat_rows = []
    for item in vulns:
        dep = item.get("dependency", "")
        parts = dep.split(":")
        if len(parts) < 3:
            continue
        group_id, artifact_id, current_version = parts[0], parts[1], parts[2]

        fixed_versions = []
        for det in item.get("details", []) or []:
            fixed_versions.extend(det.get("fixed_versions", []) or [])
        fixed_versions = list(dict.fromkeys(fixed_versions))

        # Collect vuln IDs for this dependency
        dep_vuln_ids = []
        for det in item.get("details", []) or []:
            vid = det.get("id", "")
            if vid:
                dep_vuln_ids.append(vid)

        lookup_json = json.dumps({
            "group_id": group_id,
            "artifact_id": artifact_id,
            "current_version": current_version,
            "fixed_versions": fixed_versions,
        })
        lookup_resp = MavenCentralVersionLookupTool()._run(lookup_json)
        try:
            lookup = json.loads(lookup_resp)
        except Exception:
            lookup = {}
        target_version = lookup.get("recommended_upgrade") or ""
        if not target_version and fixed_versions:
            target_version = sorted(fixed_versions, key=_parse_version_tuple)[-1]
        if not target_version:
            target_version = current_version

        upgrade = f"{group_id}:{artifact_id}:{current_version} -> {group_id}:{artifact_id}:{target_version}"
        fix_version = ", ".join(fixed_versions) or target_version or "UNKNOWN"

        # Build upgrade reason
        vuln_id_str = ", ".join(dep_vuln_ids[:3])
        target_parts = _parse_version_tuple(target_version)
        current_parts = _parse_version_tuple(current_version)
        same_major = (target_parts and current_parts and target_parts[0] == current_parts[0])
        if target_version == current_version:
            reason = "No fix available yet; monitor for updates"
        elif target_version in fixed_versions:
            reason = f"Patched release fixing {vuln_id_str}"
            if same_major:
                reason += "; same major version"
        else:
            reason = f"Latest safe release fixing {vuln_id_str}"
            if same_major:
                reason += "; same major version"

        upgrade_rows.append(f"| {dep} | {upgrade} | {reason} | {fix_version} |")

        changelog_json = json.dumps({
            "group_id": group_id,
            "artifact_id": artifact_id,
            "current_version": current_version,
            "target_version": target_version,
        })
        changelog_resp = FetchChangelogTool()._run(changelog_json)
        try:
            changelog = json.loads(changelog_resp)
        except Exception:
            changelog = {}
        breaking = changelog.get("breaking_changes", []) or []
        breaking_text = "; ".join(breaking[:3]) if breaking else "None noted"
        safe = "YES" if changelog.get("safe_to_upgrade", False) else "NO"

        usage_json = json.dumps({
            "repo_path": repo_path,
            "package_pattern": group_id,
        })
        usage_resp = SearchCodeUsageTool()._run(usage_json)
        try:
            usage = json.loads(usage_resp)
            affected = "YES" if usage.get("usage_found") else "NO"
        except Exception:
            affected = "UNKNOWN"

        compat_rows.append(
            f"| {dep} | {upgrade} | {breaking_text} | {affected} | {safe} |"
        )

    allowlist = sorted(expected_allowlist)

    report_lines = [
        "# Security Vulnerability Report",
        "",
        "## Executive Summary",
        f"The security scan identified a total of **{vuln_count}** vulnerabilities across **{total_checked}** dependencies.",
        "",
        "## Build System",
        f"The build system used for this project is **{build_system.upper()}**.",
        "",
        "## Scan Statistics",
        f"- Total Dependencies Checked: {total_checked}",
        f"- Vulnerable Count: {vuln_count}",
        f"- Safe Count: {safe_count}",
        "",
        "## Critical & High Vulnerabilities",
        "| Dependency | Vuln ID | Severity | Summary | Fix Version |",
        "| --- | --- | --- | --- | --- |",
    ]
    report_lines.extend(crit_rows)
    report_lines.extend([
        "",
        "## Medium & Low Vulnerabilities",
        "| Dependency | Vuln ID | Severity | Summary | Fix Version |",
        "| --- | --- | --- | --- | --- |",
    ])
    report_lines.extend(medlow_rows)
    report_lines.extend([
        "",
        "## Upgrade Plan",
        "| Dependency | Upgrade | Reason | Fix Version |",
        "| --- | --- | --- | --- |",
    ])
    report_lines.extend(upgrade_rows)
    report_lines.extend([
        "",
        "## Compatibility Analysis",
        "| Dependency | Upgrade | Breaking Changes | Project Affected | Safe to Upgrade |",
        "| --- | --- | --- | --- | --- |",
    ])
    report_lines.extend(compat_rows)
    report_lines.extend([
        "",
        "## Compatibility Warnings",
        "None noted." if not compat_rows else "Review breaking changes before upgrading.",
        "",
        "## Next Steps",
        "- Apply recommended upgrades and run full test suite.",
        "- Review breaking changes and update configuration as needed.",
        "",
        f"Dependency Allowlist: {json.dumps(allowlist)}",
    ])

    return "\n".join(report_lines)


def create_tasks(repo_scanner, vuln_analyst, upgrade_strategist, report_generator, repo_path: str):
    scan_task = Task(
        description=(
            f"Analyze the repository at path: {repo_path}\n\n"
            "Steps:\n"
            "1. Use the 'Detect Build System' tool with the repo path to determine if it's Maven or Gradle.\n"
            "2. Use the 'Extract Dependencies' tool with repo_path and build_system:\n"
            f'   repo_path: "{repo_path}", build_system: "<detected_system>"\n'
            "3. Return the complete list of dependencies as JSON.\n\n"
            "IMPORTANT: Pass the exact repo path as a string to the Detect Build System tool. "
            "For Extract Dependencies, pass repo_path and build_system as tool arguments."
        ),
        expected_output=(
            "A JSON object with exactly two fields:\n"
            '{"build_system": "maven or gradle", "dependencies": [...]}\n'
            "The 'dependencies' value must be the COMPLETE JSON array returned by the "
            "Extract Dependencies tool. Each object has: group_id, artifact_id, version, scope."
        ),
        agent=repo_scanner,
    )

    vuln_task = Task(
        description=(
            "Check ALL dependencies from the previous task against the OSV vulnerability database.\n\n"
            "Steps:\n"
            "1. Find the 'dependencies' JSON array from the previous task.\n"
            "2. Pass that ENTIRE array to the 'Check OSV Vulnerabilities' tool.\n"
            "3. Return the tool's full JSON result as-is.\n\n"
            "IMPORTANT: The tool expects a JSON ARRAY of dependency objects. "
            "Pass all dependencies in a single call.\n\n"
            "CRITICAL: After getting the results, COUNT the vulnerable dependencies. "
            "The vulnerable_count in your output MUST match the number of entries in "
            "the vulnerabilities array. Do NOT drop or omit any vulnerability — every "
            "single one matters, especially CRITICAL ones like Log4Shell (log4j)."
        ),
        expected_output=(
            "The full JSON vulnerability report returned by the tool, containing:\n"
            "- total_dependencies_checked, vulnerable_count, safe_count\n"
            "- vulnerabilities array with ALL dependency coordinates, IDs, severity, summaries, "
            "and fixed versions.\n"
            "You MUST include every vulnerability. Do NOT summarize or omit entries."
        ),
        agent=vuln_analyst,
        context=[scan_task],
    )

    upgrade_task = Task(
        description=(
            "For each vulnerable dependency, find the best UPGRADE version, read its "
            "changelog, and verify compatibility with the project.\n\n"
            "CRITICAL RULES:\n"
            "- ALWAYS recommend an UPGRADE (newer version). NEVER recommend a downgrade.\n"
            "- The recommended version must be NEWER than the current version.\n"
            "- ALWAYS fetch the changelog before recommending an upgrade.\n\n"
            "Steps for EACH vulnerable dependency:\n"
            "1. Use the 'Search Code Usage' tool to find how the dependency is used:\n"
            f'   repo_path: "{repo_path}", package_pattern: "<package.name>"\n'
            "2. Use the 'Lookup Latest Safe Version' tool:\n"
            '   group_id: "...", artifact_id: "...", current_version: "...", fixed_versions: ["..."]\n'
            "3. Use the 'Fetch Changelog' tool to get release notes between current and target:\n"
            '   group_id: "...", artifact_id: "...", current_version: "...", target_version: "<recommended_upgrade>"\n'
            "4. If the changelog shows breaking changes, use the 'Read Project Docs' tool to check "
            "if those changes affect this project:\n"
            f'   repo_path: "{repo_path}", search_terms: ["<affected_feature>", ...]\n'
            "5. Assess compatibility combining code usage, changelog, and project docs.\n"
            "6. Set safe_to_upgrade: true/false with clear reasoning.\n\n"
            "IMPORTANT: Use all relevant tools for EACH vulnerable dependency."
        ),
        expected_output=(
            "A JSON array of upgrade recommendations with: dependency, current_version, "
            "recommended_version, risk_level, compatibility_notes, code_usage, "
            "affected_files, vulnerabilities_fixed, changelog_summary, breaking_changes, "
            "safe_to_upgrade (boolean), migration_steps."
        ),
        agent=upgrade_strategist,
        context=[scan_task, vuln_task],
    )

    report_task = Task(
        description=(
            "Generate a comprehensive security vulnerability report in Markdown.\n\n"
            "CRITICAL RULE: You MUST include EVERY vulnerability from the previous tasks. "
            "Cross-check: count the vulnerabilities in the data you received. Your report "
            "tables MUST have the same total number of rows. Do NOT skip any dependency. "
            "CRITICAL: ONLY include dependencies that appear in the vulnerability data. "
            "Do NOT add or invent dependencies that were not reported by the scanner.\n\n"
            "REQUIRED SECTIONS:\n"
            "1. Executive Summary — mention total vulns found and most critical ones by name\n"
            "2. Build System\n"
            "3. Scan Statistics — exact counts from the vulnerability data\n"
            "4. Critical & High Vulnerabilities (table) — one row per vuln ID\n"
            "5. Medium & Low Vulnerabilities (table) — one row per vuln ID\n"
            "6. Upgrade Plan — one row per vulnerable dependency\n"
            "7. Compatibility Analysis — for each upgrade, show:\n"
            "   - What breaking changes exist (from changelog data)\n"
            "   - Whether the project is affected (based on code usage and project docs)\n"
            "   - Required migration steps (if any)\n"
            "   - Safe to upgrade: YES/NO with reasoning\n"
            "8. Compatibility Warnings\n"
            "9. Next Steps\n"
            "10. Dependency Allowlist — MUST be a single line:\n"
            '   Dependency Allowlist: ["group:artifact:version", "..."]\n\n'
            "CRITICAL FORMAT RULES:\n"
            "- In ALL tables, the Dependency column MUST be 'group_id:artifact_id:version'.\n"
            "- The allowlist MUST EXACTLY match the vulnerability data dependencies.\n"
            "- Do NOT mention any dependency not present in the allowlist.\n\n"
            "NO-VULNERABILITY RULES:\n"
            "- If zero vulnerabilities are found, the allowlist MUST be an empty array []\n"
            "- Upgrade Plan and Compatibility Analysis MUST contain no data rows.\n\n"
            "UPGRADE FORMAT RULE:\n"
            "- The Upgrade column MUST include explicit versions in the form "
            "'<group:artifact:version> -> <group:artifact:version>'.\n\n"
            "TABLE FORMAT for vulnerabilities:\n"
            "| Dependency | Vuln ID | Severity | Summary | Fix Version |\n"
            "| --- | --- | --- | --- | --- |\n\n"
            "TABLE FORMAT for Upgrade Plan:\n"
            "| Dependency | Upgrade | Reason | Fix Version |\n"
            "| --- | --- | --- | --- |\n"
            "The Reason column MUST explain WHY this version was chosen, e.g.:\n"
            "- 'Patched release fixing GHSA-xxx; same major version'\n"
            "- 'Latest safe release fixing GHSA-xxx'\n"
            "- 'No fix available yet; monitor for updates'\n\n"
            "TABLE FORMAT for Compatibility Analysis:\n"
            "| Dependency | Upgrade | Breaking Changes | Project Affected | Safe to Upgrade |\n"
            "| --- | --- | --- | --- | --- |\n\n"
            "VERIFICATION: Before finishing, count your table rows. If any dependency from "
            "the vulnerability data is missing from your tables, ADD IT."
        ),
        expected_output=(
            "A complete Markdown security report with all 9 sections including Compatibility Analysis. "
            "Every vulnerability must appear in the tables — none omitted. "
            "The Compatibility Analysis section must show changelog findings and upgrade safety. "
            "Do NOT wrap the output in code fences."
        ),
        agent=report_generator,
        context=[scan_task, vuln_task, upgrade_task],
    )

    return [scan_task, vuln_task, upgrade_task, report_task]


def resolve_repo_path(input_path: str) -> tuple[str, str | None]:
    is_url = (
        re.match(r"https?://github\.com/", input_path)
        or input_path.endswith(".git")
    )
    if not is_url:
        return input_path, None

    tmp_dir = tempfile.mkdtemp(prefix="vulnhawk_")
    print(f"Cloning {input_path} -> {tmp_dir} ...")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", input_path, tmp_dir],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"ERROR: git clone failed:\n{result.stderr.strip()}")
        sys.exit(1)
    print("Clone complete.\n")
    return tmp_dir, tmp_dir


def run_scan(repo_path: str) -> str:
    repo_path = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path):
        print(f"ERROR: Repository path does not exist: {repo_path}")
        sys.exit(1)

    if os.getenv("VULNHAWK_FAST", "").lower() in ("1", "true", "yes"):
        expected_build_system, expected_allowlist, expected_vuln_ids = _compute_vuln_expectations(repo_path)
        report_text = _build_fallback_report(repo_path)
        if "dependency allowlist" not in report_text.lower():
            report_text = report_text.rstrip() + "\n\n" + f"Dependency Allowlist: {json.dumps(sorted(expected_allowlist))}"
        validate_report_dependencies(
            report_text,
            expected_build_system,
            expected_allowlist,
            expected_vuln_ids,
            strict_upgrade_coverage=False,
        )
        report_filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = os.path.join(os.getcwd(), report_filename)
        with open(report_path, "w") as f:
            f.write(report_text)
        print("\n" + "=" * 60)
        print("  SCAN COMPLETE (FAST MODE)")
        print(f"  Report saved to: {report_path}")
        print("=" * 60)
        return report_text

    from agents import LLM_VENDOR, OLLAMA_URL, OLLAMA_MODEL, GOOGLE_MODEL

    if LLM_VENDOR == "google":
        llm_label = f"gemini/{GOOGLE_MODEL}"
    else:
        llm_label = f"ollama/{OLLAMA_MODEL} @ {OLLAMA_URL}"

    print("=" * 60)
    print("  VULNHAWK - AI Vulnerability Scanner")
    print(f"  Repository: {repo_path}")
    print(f"  LLM:        {llm_label}")
    print(f"  Started:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()

    print("[1/4] Creating AI agents...")
    repo_scanner, vuln_analyst, upgrade_strategist, report_generator = create_agents()

    print("[2/4] Defining tasks...")
    tasks = create_tasks(
        repo_scanner, vuln_analyst, upgrade_strategist, report_generator, repo_path
    )

    print("[3/4] Assembling crew...")
    crew = Crew(
        agents=[repo_scanner, vuln_analyst, upgrade_strategist, report_generator],
        tasks=tasks,
        process=Process.sequential,
        verbose=True,
    )

    print("[4/4] Running vulnerability scan...\n")
    result = crew.kickoff()

    report_filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path = os.path.join(os.getcwd(), report_filename)
    report_text = clean_report(str(result))
    try:
        expected_build_system, expected_allowlist, expected_vuln_ids = _compute_vuln_expectations(repo_path)
        validate_report_dependencies(
            report_text,
            expected_build_system,
            expected_allowlist,
            expected_vuln_ids,
            strict_upgrade_coverage=False,
        )
    except ValueError as e:
        invalid_name = f"vulnerability_report_INVALID_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        invalid_path = os.path.join(os.getcwd(), invalid_name)
        with open(invalid_path, "w") as f:
            f.write(report_text)
        try:
            fallback_text = _build_fallback_report(repo_path)
            validate_report_dependencies(
                fallback_text,
                expected_build_system,
                expected_allowlist,
                expected_vuln_ids,
                strict_upgrade_coverage=False,
            )
            with open(report_path, "w") as f:
                f.write(fallback_text)
            print("\n" + "=" * 60)
            print("  SCAN COMPLETED WITH FALLBACK REPORT")
            print(f"  Reason: {e}")
            print(f"  Invalid report saved to: {invalid_path}")
            print(f"  Fallback report saved to: {report_path}")
            print("=" * 60)
            return fallback_text
        except Exception as fallback_err:
            print("\n" + "=" * 60)
            print("  SCAN FAILED VALIDATION")
            print(f"  Reason: {e}")
            print(f"  Invalid report saved to: {invalid_path}")
            print(f"  Fallback generation failed: {fallback_err}")
            print("=" * 60)
            sys.exit(1)
        print("\n" + "=" * 60)
        print("  SCAN FAILED VALIDATION")
        print(f"  Reason: {e}")
        print(f"  Invalid report saved to: {invalid_path}")
        print("=" * 60)
        sys.exit(1)

    with open(report_path, "w") as f:
        f.write(report_text)

    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print(f"  Report saved to: {report_path}")
    print("=" * 60)

    return report_text


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("VulnHawk - AI Vulnerability Scanner")
        print()
        print("Usage: python main.py [--fast] <path-or-github-url>")
        print()
        print("Example:")
        print("  python main.py /home/user/projects/my-spring-app")
        print("  python main.py ./my-project")
        print("  python main.py https://github.com/user/some-java-project")
        print("  python main.py --fast /home/user/projects/my-spring-app")
        print()
        print("API mode:")
        print("  cd app && uvicorn main:app --host 0.0.0.0 --port 8000")
        sys.exit(1)

    args = sys.argv[1:]
    if "--fast" in args:
        os.environ["VULNHAWK_FAST"] = "1"
        args = [a for a in args if a != "--fast"]

    if not args:
        print("ERROR: Missing repository path or URL.")
        sys.exit(1)

    repo_path, tmp_dir = resolve_repo_path(args[0])
    try:
        run_scan(repo_path)
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            print(f"Cleaned up temporary clone: {tmp_dir}")
