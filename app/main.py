"""
VulnHawk - FastAPI Server
API-powered vulnerability scanner using CrewAI + Ollama.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000
"""

import asyncio
from contextlib import asynccontextmanager
import hashlib
import os
import pathlib
import re
import json
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import httpx
from datetime import datetime, timezone
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from crewai import Crew, Process, Task

from agents import create_agents, get_llm, LLM_VENDOR, OLLAMA_URL
from tools import (
    OSVVulnerabilityCheckTool,
    DetectBuildSystemTool,
    ExtractDependenciesTool,
    MavenCentralVersionLookupTool,
    FetchChangelogTool,
    SearchCodeUsageTool,
)

load_dotenv()

# ── Database ──────────────────────────────────────────────────────────────────
# SQLite at /data/vulnhawk.db (Docker volume) or ./vulnhawk.db locally.
_DB_PATH = os.getenv("VULNHAWK_DB", str(pathlib.Path(__file__).parent.parent / "vulnhawk.db"))
_OSV_CACHE_TTL_HOURS = 24


def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db() -> None:
    parent = os.path.dirname(_DB_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with _db_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_key     TEXT NOT NULL,
                display_name TEXT NOT NULL,
                input_type   TEXT NOT NULL,
                build_system TEXT,
                total_deps   INTEGER,
                vuln_count   INTEGER,
                report_md    TEXT NOT NULL,
                scanned_at   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_key ON scans(scan_key);
            CREATE INDEX IF NOT EXISTS idx_scans_at  ON scans(scanned_at DESC);

            CREATE TABLE IF NOT EXISTS osv_cache (
                cache_key  TEXT PRIMARY KEY,
                vuln_json  TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            );
        """)


def _scan_key_for_url(url: str) -> tuple[str, str]:
    """Return (scan_key, display_name) for a GitHub URL.

    scan_key  = 'owner/repo'   (stable, used for history grouping)
    display_name = 'repo'      (short name shown in UI)
    """
    # Strip scheme, host, trailing .git, query strings
    path = re.sub(r"https?://github\.com/", "", url.strip().rstrip("/"))
    path = re.sub(r"\.git$", "", path)
    parts = path.split("/")
    key = "/".join(parts[:2]) if len(parts) >= 2 else path
    name = parts[1] if len(parts) >= 2 else path
    return key, name


def _scan_key_for_deps(dep_input: str) -> tuple[str, str]:
    """Return (scan_key, display_name) for a raw dep-list scan."""
    lines = sorted(l.strip() for l in dep_input.splitlines() if l.strip() and not l.strip().startswith("#"))
    digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()[:12]
    n = len(lines)
    return f"dep-list:{digest}", f"Dep list ({n} deps)"


def db_save_scan(
    scan_key: str,
    display_name: str,
    input_type: str,
    build_system: str,
    report_md: str,
) -> int:
    """Save a completed scan and return its new row id."""
    # Parse stats from the report
    total = 0
    vuln  = 0
    m = re.search(r"Total Dependencies Checked[:\s]+(\d+)", report_md, re.IGNORECASE)
    if m:
        total = int(m.group(1))
    m = re.search(r"Vulnerable Count[:\s]+(\d+)", report_md, re.IGNORECASE)
    if m:
        vuln = int(m.group(1))

    with _db_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scans
               (scan_key, display_name, input_type, build_system, total_deps, vuln_count, report_md, scanned_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (scan_key, display_name, input_type, build_system or "",
             total, vuln, report_md, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        return cur.lastrowid


def db_get_osv_cache(deps_hash: str) -> str | None:
    """Return cached OSV JSON if still fresh, else None."""
    with _db_conn() as conn:
        row = conn.execute(
            "SELECT vuln_json, fetched_at FROM osv_cache WHERE cache_key=?", (deps_hash,)
        ).fetchone()
    if not row:
        return None
    fetched = datetime.fromisoformat(row["fetched_at"])
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    age_hours = (datetime.now(timezone.utc) - fetched).total_seconds() / 3600
    return row["vuln_json"] if age_hours < _OSV_CACHE_TTL_HOURS else None


def db_set_osv_cache(deps_hash: str, vuln_json: str) -> None:
    with _db_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO osv_cache (cache_key, vuln_json, fetched_at) VALUES (?,?,?)",
            (deps_hash, vuln_json, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_db()
    yield


app = FastAPI(
    title="VulnHawk",
    description="AI-powered vulnerability scanner using CrewAI",
    version="1.0.0",
    lifespan=lifespan,
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
    # Strip <think>...</think> reasoning traces (Gemini 2.5, DeepSeek, etc.)
    # Handle both closed tags and unclosed tags (DeepSeek sometimes omits </think>)
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
        dep = cols[0].strip("` *_").strip()
        if not dep or dep.lower() in ("dependency", "none", "n/a", "-"):
            continue
        deps.add(dep)
        if current_section not in sections:
            sections[current_section] = set()
        sections[current_section].add(dep)
        if current_section not in vuln_ids:
            vuln_ids[current_section] = set()
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


def _parse_vuln_json(vuln_json: str) -> tuple[set[str], set[str], list[dict]]:
    """Extract (allowlist, vuln_ids, vuln_summary) from a pre-computed OSV JSON string."""
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
        dep = item.get("dependency", "")
        parts = dep.split(":")
        if len(parts) >= 3:
            allowlist.add(f"{parts[0]}:{parts[1]}:{parts[2]}")
        for vid in item.get("vulnerability_ids", []) or []:
            if vid:
                vuln_ids.add(vid)
        # severity and fixed_versions live inside details[], not at item level
        details = item.get("details", []) or []
        severity = ""
        item_fixed: list[str] = []
        for det in details:
            sev = det.get("severity", "")
            if sev and sev not in ("UNKNOWN", "") and not severity:
                severity = sev
            for fv in det.get("fixed_versions", []) or []:
                if fv and fv not in item_fixed:
                    item_fixed.append(fv)
        vuln_summary.append({
            "dependency": dep,
            "vuln_ids": item.get("vulnerability_ids", []),
            "severity": severity,
            "fixed_versions": item_fixed,
            "summary": details[0].get("summary", "") if details else "",
        })
    return allowlist, vuln_ids, vuln_summary


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


def _build_fallback_report(
    scan_path: str,
    build_system: str,
    vuln_json: str,
    expected_allowlist: set[str],
    deps_json: str = "",
) -> str:
    """Generate a deterministic Markdown report directly from pre-computed OSV data.

    Used as a fallback when the LLM report fails validation. Calls
    MavenCentralVersionLookupTool, FetchChangelogTool, and SearchCodeUsageTool
    for each vulnerable dependency to fill the Upgrade Plan and Compatibility
    Analysis tables.
    """
    vuln_report: dict = {}
    if vuln_json:
        try:
            vuln_report = json.loads(vuln_json)
        except Exception:
            pass

    vulns = vuln_report.get("vulnerabilities", [])
    total_checked = vuln_report.get("total_dependencies_checked", 0)
    vuln_count = vuln_report.get("vulnerable_count", 0)
    safe_count = vuln_report.get("safe_count", 0)

    def _trunc_summary(text: str, limit: int = 120) -> str:
        """Truncate at sentence boundary to avoid mid-sentence cuts in table cells."""
        if len(text) <= limit:
            return text
        # Try to break at the last period before the limit
        idx = text.rfind(". ", 0, limit)
        if idx > limit // 2:
            return text[: idx + 1]
        # Fall back to last space
        idx = text.rfind(" ", 0, limit)
        if idx > 0:
            return text[:idx] + "…"
        return text[:limit] + "…"

    def _min_fix(fixed_versions: list) -> str:
        """Return the lowest fixed version (most compatible), or '—'."""
        if not fixed_versions:
            return "—"
        try:
            return sorted(fixed_versions, key=_parse_version_tuple)[0]
        except Exception:
            return fixed_versions[0]

    # Build vuln rows — one row per vuln ID in vulnerability_ids.
    # OSVVulnerabilityCheckTool only fetches full details for the first 5 IDs;
    # for the rest we emit a stub row so every ID appears in the tables and
    # validation does not fail with "missing IDs".
    crit_rows: list[str] = []
    medlow_rows: list[str] = []
    for item in vulns:
        dep = item.get("dependency", "")
        details = item.get("details", []) or []
        # Index details by their ID for O(1) lookup
        detail_map: dict[str, dict] = {d.get("id", ""): d for d in details}
        for vid in item.get("vulnerability_ids", []) or []:
            if not vid:
                continue
            det = detail_map.get(vid, {})
            sev = det.get("severity", "UNKNOWN") or "UNKNOWN"
            summary = det.get("summary", "Details not fetched") or "Details not fetched"
            fixed = _min_fix(det.get("fixed_versions", []) or [])
            row = f"| {dep} | {vid} | {sev} | {_trunc_summary(summary)} | {fixed} |"
            if sev in ("CRITICAL", "HIGH"):
                crit_rows.append(row)
            else:
                medlow_rows.append(row)

    # Build upgrade/compat rows per vulnerable dependency
    upgrade_rows: list[str] = []
    compat_rows: list[str] = []
    for item in vulns:
        dep = item.get("dependency", "")
        parts = dep.split(":")
        if len(parts) < 3:
            continue
        group_id, artifact_id, current_version = parts[0], parts[1], parts[2]

        fixed_versions: list[str] = []
        for det in item.get("details", []) or []:
            fixed_versions.extend(det.get("fixed_versions", []) or [])
        fixed_versions = list(dict.fromkeys(fixed_versions))

        dep_vuln_ids: list[str] = []
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
        try:
            lookup_resp = MavenCentralVersionLookupTool()._run(lookup_json)
            lookup = json.loads(lookup_resp)
        except Exception:
            lookup = {}
        target_version: str = lookup.get("recommended_upgrade") or ""
        if not target_version and fixed_versions:
            target_version = sorted(fixed_versions, key=_parse_version_tuple)[-1]
        if not target_version:
            target_version = current_version

        # "v1 → v2" in Upgrade column — dep name is already in the first column
        upgrade = f"{current_version} → {target_version}"
        fix_version = _min_fix(fixed_versions) if fixed_versions else (target_version or "UNKNOWN")

        vuln_id_str = ", ".join(dep_vuln_ids[:3])
        target_parts = _parse_version_tuple(target_version)
        current_parts = _parse_version_tuple(current_version)
        same_major = bool(target_parts and current_parts and target_parts[0] == current_parts[0])
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
        try:
            changelog_resp = FetchChangelogTool()._run(changelog_json)
            changelog = json.loads(changelog_resp)
        except Exception:
            changelog = {}
        breaking = changelog.get("breaking_changes", []) or []
        # Truncate each breaking change to keep table cells readable
        breaking_text = "; ".join(_trunc_summary(b, 80) for b in breaking[:2]) if breaking else "None noted"
        safe = "YES" if changelog.get("safe_to_upgrade", False) else "NO"

        usage_json = json.dumps({
            "repo_path": scan_path,
            "package_pattern": group_id,
        })
        try:
            usage_resp = SearchCodeUsageTool()._run(usage_json)
            usage = json.loads(usage_resp)
            affected = "YES" if usage.get("usage_found") else "NO"
        except Exception:
            affected = "UNKNOWN"

        compat_rows.append(
            f"| {dep} | {upgrade} | {breaking_text} | {affected} | {safe} |"
        )

    allowlist = sorted(expected_allowlist)

    # ── Build dependency overview rows (all deps, vuln/safe status) ──────────
    # Build a map: "group_id:artifact_id:version" → list of vuln IDs
    vuln_dep_map: dict[str, list[str]] = {}
    for item in vulns:
        dep_key = item.get("dependency", "")
        vids = [v for v in (item.get("vulnerability_ids") or []) if v]
        if dep_key and vids:
            vuln_dep_map[dep_key] = vids

    dep_overview_rows: list[str] = []
    all_deps_parsed: list[dict] = []
    if deps_json:
        try:
            all_deps_parsed = json.loads(deps_json)
        except Exception:
            pass

    for dep_obj in all_deps_parsed:
        g = dep_obj.get("group_id", "")
        a = dep_obj.get("artifact_id", "")
        v = dep_obj.get("version", "")
        scope = dep_obj.get("scope", "compile")
        depth = dep_obj.get("depth", 0)
        kind = "Direct" if depth == 0 else f"Transitive (d{depth})"
        if not (g and a and v):
            continue
        coord = f"{g}:{a}:{v}"
        if coord in vuln_dep_map:
            vids_str = ", ".join(vuln_dep_map[coord][:2])
            if len(vuln_dep_map[coord]) > 2:
                vids_str += f" (+{len(vuln_dep_map[coord])-2} more)"
            status = "VULNERABLE"
        else:
            vids_str = "—"
            status = "SAFE"
        dep_overview_rows.append(f"| {coord} | {kind} | {scope} | {status} | {vids_str} |")

    report_lines = [
        "# Security Vulnerability Report",
        "",
        "## 1. Executive Summary",
        (
            f"The security scan identified **{vuln_count}** vulnerabilities "
            f"across **{total_checked}** dependencies."
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
        "| Dependency | Vuln ID | Severity | Summary | Fix Version |",
        "| --- | --- | --- | --- | --- |",
    ]
    report_lines.extend(crit_rows)
    report_lines.extend([
        "",
        "## 5. Medium & Low Vulnerabilities",
        "| Dependency | Vuln ID | Severity | Summary | Fix Version |",
        "| --- | --- | --- | --- | --- |",
    ])
    report_lines.extend(medlow_rows)
    report_lines.extend([
        "",
        "## 6. Upgrade Plan",
        "| Dependency | Upgrade | Reason | Fix Version |",
        "| --- | --- | --- | --- |",
    ])
    report_lines.extend(upgrade_rows)
    report_lines.extend([
        "",
        "## 7. Compatibility Analysis",
        "| Dependency | Upgrade | Breaking Changes | Project Affected | Safe to Upgrade |",
        "| --- | --- | --- | --- | --- |",
    ])
    report_lines.extend(compat_rows)
    report_lines.extend([
        "",
        "## 8. Compatibility Warnings",
        "None noted." if not compat_rows else "Review breaking changes before upgrading.",
        "",
        "## 9. Next Steps",
        "- Apply recommended upgrades and run the full test suite.",
        "- Review breaking changes and update configuration as needed.",
    ])

    # Dependency overview section (all scanned deps)
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
        # Build tool not available in this environment (e.g. no Java/Maven) — skip verification
        return build_system, set(), set()
    if not isinstance(deps, list) or not deps:
        # No extractable deps (version catalogs, unresolvable variables, etc.) — skip verification
        return build_system, set(), set()

    vuln_json = OSVVulnerabilityCheckTool()._run(json.dumps(deps))
    try:
        vuln_report = json.loads(vuln_json)
    except Exception:
        # OSV returned non-JSON (e.g. "No dependencies to check.") — skip verification
        return build_system, set(), set()
    if not isinstance(vuln_report, dict):
        return build_system, set(), set()

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

    if strict_upgrade_coverage:
        bad_upgrades = []
        for up in extracted["upgrades"]:
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
            # Allow up to 15% missing — large vuln lists always have minor LLM gaps.
            tolerance = max(2, round(len(allowlist) * 0.15))
            if len(missing_upgrade) > tolerance:
                raise ValueError(
                    "Upgrade Plan missing dependencies: " + ", ".join(missing_upgrade)
                )

            missing_compat = sorted(d for d in allowlist if d not in compat_deps)
            if missing_compat:
                raise ValueError(
                    "Compatibility Analysis missing dependencies: " + ", ".join(missing_compat)
                )

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


def create_tasks(
    repo_scanner, vuln_analyst, upgrade_strategist, report_generator,
    repo_path: str,
    build_system: str = "",
    deps_json: str = "",
    vuln_summary: list | None = None,
):
    """Create the full 5-task pipeline for repo scanning.

    build_system, deps_json, and vuln_summary are pre-computed before agents
    run so the LLMs never have to parse large JSON from context.
    """
    n_deps = 0
    if deps_json:
        try:
            n_deps = len(json.loads(deps_json))
        except Exception:
            pass

    vuln_summary = vuln_summary or []
    n_vulns = len(vuln_summary)

    # upgrade_task gets full detail (severity + first 3 CVEs) so the strategist
    # can look up the right versions.  report_task gets dep names only — the
    # massive CVE lists overwhelm smaller models and cause them to go off-script.
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

    # ── Task 1: Build system detection ───────────────────────────────────────
    if build_system:
        build_task = Task(
            description=(
                f"The build system for the repository at {repo_path} has already been "
                f"detected as: **{build_system}**.\n\n"
                "Confirm this result and return it."
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
                f"Here is the full dependency list:\n\n{deps_json}\n\n"
                "Return this exact JSON array as your output. Do NOT modify it."
            ),
            expected_output=(
                f"The complete JSON array of {n_deps} dependencies. "
                "Each object has: group_id, artifact_id, version, scope."
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
                "Pass repo_path and build_system as arguments. "
                "Return the complete JSON array from the tool."
            ),
            expected_output=(
                "The complete JSON array of dependencies. "
                "Each object has: group_id, artifact_id, version, scope."
            ),
            agent=repo_scanner,
            context=[build_task],
        )

    # ── Task 3: Vulnerability check ───────────────────────────────────────────
    vuln_task = Task(
        description=(
            "Check ALL dependencies from the previous task against the OSV vulnerability database.\n\n"
            "The previous task output is a JSON array of dependencies.\n\n"
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
            "and fixed versions. Do NOT summarize or omit entries."
        ),
        agent=vuln_analyst,
        context=[dep_task],
    )

    upgrade_task = Task(
        description=(
            f"You MUST produce upgrade recommendations for ALL {n_vulns} vulnerable dependencies listed below. "
            "Do NOT skip any entry.\n\n"
            f"COMPLETE LIST OF VULNERABLE DEPENDENCIES ({n_vulns} total):\n"
            f"{vuln_checklist}\n\n"
            "For EACH entry above, find the best UPGRADE version, read its changelog, "
            "and verify compatibility with the project.\n\n"
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
        context=[dep_task, vuln_task],
    )

    report_task = Task(
        description=(
            "Generate a comprehensive security vulnerability report in Markdown.\n\n"
            f"Build System: {build_system or 'see previous task'}\n\n"
            "Your ONLY job is to write a Markdown security report based on the vulnerability "
            "and upgrade data from the previous tasks. Do NOT output JSON. Do NOT modify "
            "dependencies. Do NOT explain code. ONLY write the Markdown report.\n\n"
            f"MANDATORY: Your Upgrade Plan and Compatibility Analysis tables MUST contain "
            f"exactly {n_vulns} data rows — one for each vulnerable dependency below:\n"
            f"{dep_names_list}\n\n"
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
            "- The Upgrade column MUST use ASCII '->' (hyphen + greater-than), "
            "NOT the Unicode arrow '→'.\n"
            "- ALWAYS include the full group ID and artifact ID on BOTH sides. "
            "Example: 'org.assertj:assertj-core:3.27.6 -> org.assertj:assertj-core:3.27.7'.\n"
            "- NEVER write abbreviated versions like '1.5.21 -> 1.5.25' — "
            "both sides MUST be 'group:artifact:version'.\n"
            "- When no fix is available, repeat the current version on both sides: "
            "'group:artifact:current_version -> group:artifact:current_version'.\n"
            "- NEVER use 'N/A' or any non-version placeholder in the Upgrade column.\n\n"
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
        context=[vuln_task, upgrade_task],
    )

    return [build_task, dep_task, vuln_task, upgrade_task, report_task]


def _run_full_scan(scan_path: str) -> str:
    """Synchronous full-repo scan — runs in a thread via asyncio.to_thread.

    Fast mode (VULNHAWK_FAST=1) or Ollama backend: skips the LLM report agent
    and generates a deterministic report directly from pre-computed OSV data.
    Ollama models (DeepSeek, etc.) reliably fail instruction-following for the
    complex report-generation task, so fast mode is the default for Ollama.
    """
    # ── Step 1: Pre-compute build system + full transitive dep tree ───────────
    build_system = DetectBuildSystemTool()._run(scan_path)
    if build_system.startswith("ERROR") or build_system == "unknown":
        raise ValueError(f"Failed to detect build system: {build_system}")

    deps_json = ExtractDependenciesTool()._run(scan_path, build_system)
    try:
        json.loads(deps_json)
    except Exception:
        deps_json = ""  # tool unavailable; let agents call it themselves

    # ── Step 2: Pre-compute vulnerabilities ───────────────────────────────────
    vuln_json = ""
    expected_allowlist: set[str] = set()
    expected_vuln_ids: set[str] = set()
    vuln_summary: list[dict] = []
    if deps_json:
        # Check OSV cache first (keyed by SHA-256 of the deps JSON)
        deps_hash = hashlib.sha256(deps_json.encode()).hexdigest()
        raw_vuln = db_get_osv_cache(deps_hash)
        if raw_vuln:
            print(f"[VulnHawk] OSV cache hit for deps_hash={deps_hash[:12]}")
        else:
            raw_vuln = OSVVulnerabilityCheckTool()._run(deps_json)
            db_set_osv_cache(deps_hash, raw_vuln)
        try:
            json.loads(raw_vuln)
            vuln_json = raw_vuln
            expected_allowlist, expected_vuln_ids, vuln_summary = _parse_vuln_json(vuln_json)
        except Exception:
            pass

    # ── Step 3: Decide whether to use the LLM pipeline or go straight to the
    #           deterministic fallback.
    #
    # Fast mode is enabled when:
    #   - VULNHAWK_FAST=1 is set explicitly, OR
    #   - LLM_VENDOR=ollama (Ollama/DeepSeek models consistently fail the
    #     complex report-generation task and waste 10-15 min of inference time)
    fast_mode = (
        os.getenv("VULNHAWK_FAST", "").lower() in ("1", "true", "yes")
        or LLM_VENDOR == "ollama"
    )

    if not fast_mode:
        # ── LLM pipeline (Google Gemini / cloud models only) ─────────────────
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
        result = crew.kickoff()
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
            print(f"[VulnHawk] LLM report failed validation ({llm_err}). Falling back to deterministic report.")

    else:
        print(f"[VulnHawk] Fast mode active (LLM_VENDOR={LLM_VENDOR}). Skipping LLM report generation.")

    # ── Step 4: Deterministic report ─────────────────────────────────────────
    fallback_text = _build_fallback_report(scan_path, build_system, vuln_json, expected_allowlist, deps_json)
    validate_report_dependencies(
        fallback_text,
        build_system,
        expected_allowlist,
        expected_vuln_ids,
        strict_upgrade_coverage=False,
    )
    return fallback_text


def _expand_maven_deps(coords: list[dict]) -> list[dict]:
    """Fully resolve all transitive Maven dependencies via recursive POM fetching.

    Algorithm:
      - BFS over the dependency graph
      - For each artifact, fetch its POM from Maven Central
      - Walk the parent POM chain to collect inherited <properties> and
        <dependencyManagement> (including BOM imports)
      - Use the merged dep-management map to resolve unversioned deps
      - Deduplicate by group:artifact (first/nearest version wins, like Maven)
      - Deduplication by group:artifact prevents infinite loops naturally
    """
    MAX_DEPS = 10_000  # effectively unlimited; real trees top out ~500 deps
    SKIP_SCOPES = {"test", "provided", "system"}
    pom_cache: dict[str, dict] = {}  # "g:a:v" -> parsed data, shared across calls

    def pom_url(g: str, a: str, v: str) -> str:
        return f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom"

    def fetch_pom(g: str, a: str, v: str) -> dict:
        """Fetch + parse one POM. Returns {props, dep_mgmt, direct} or {}."""
        key = f"{g}:{a}:{v}"
        if key in pom_cache:
            return pom_cache[key]
        pom_cache[key] = {}  # mark in-progress to break cycles

        try:
            resp = httpx.get(pom_url(g, a, v), timeout=15, follow_redirects=True)
            if resp.status_code != 200:
                return {}
            root = ET.fromstring(resp.text)
        except Exception:
            return {}

        m = re.match(r"\{(.+?)\}", root.tag)
        ns = f"{{{m.group(1)}}}" if m else ""

        def txt(elem, tag: str, default: str = "") -> str:
            return (elem.findtext(f"{ns}{tag}", default) or default).strip()

        # ── 1. Resolve parent chain first ────────────────────────────────────
        parent_props: dict[str, str] = {}
        parent_dep_mgmt: dict[str, str] = {}
        parent_elem = root.find(f"{ns}parent")
        if parent_elem is not None:
            pg = txt(parent_elem, "groupId")
            pa = txt(parent_elem, "artifactId")
            pv = txt(parent_elem, "version")
            if pg and pa and pv and not pv.startswith("${"):
                pd = fetch_pom(pg, pa, pv)
                parent_props = pd.get("props", {})
                parent_dep_mgmt = pd.get("dep_mgmt", {})

        # ── 2. Collect local <properties> (override parent) ──────────────────
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
            """Resolve ${property} references, up to 3 hops."""
            for _ in range(3):
                if not val.startswith("${"):
                    break
                val = props.get(val[2:-1], val)
            return val

        # ── 3. Build <dependencyManagement> map (parent + BOM imports + local) ─
        dep_mgmt: dict[str, str] = dict(parent_dep_mgmt)
        dm_elem = root.find(f"{ns}dependencyManagement/{ns}dependencies")
        if dm_elem is not None:
            for d in dm_elem.findall(f"{ns}dependency"):
                dg  = resolve(txt(d, "groupId"))
                da  = resolve(txt(d, "artifactId"))
                dv  = resolve(txt(d, "version"))
                ds  = txt(d, "scope", "compile")
                if ds == "import" and dg and da and dv and not dv.startswith("${"):
                    # BOM import — merge its dep_mgmt into ours
                    bom = fetch_pom(dg, da, dv)
                    for k, bv in bom.get("dep_mgmt", {}).items():
                        dep_mgmt.setdefault(k, bv)
                elif dg and da and dv and not dv.startswith("${"):
                    dep_mgmt[f"{dg}:{da}"] = dv

        # ── 4. Collect direct <dependencies> ─────────────────────────────────
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

                # Version may be managed (not declared inline)
                if not dv or dv.startswith("${"):
                    dv = dep_mgmt.get(f"{dg}:{da}", "")

                if dg and da and dv and not dv.startswith("${"):
                    direct.append({"group_id": dg, "artifact_id": da,
                                   "version": dv, "scope": ds})

        result = {"props": props, "dep_mgmt": dep_mgmt, "direct": direct}
        pom_cache[key] = result
        return result

    # ── BFS over the full dependency graph ────────────────────────────────────
    seen: dict[str, str] = {}   # group:artifact -> version (nearest wins)
    resolved: list[dict] = []
    queue: list[dict] = list(coords)

    while queue and len(resolved) < MAX_DEPS:
        dep = queue.pop(0)
        g = dep.get("group_id", "").strip()
        a = dep.get("artifact_id", "").strip()
        v = dep.get("version", "").strip()

        if not g or not a or not v or v == "UNKNOWN":
            continue

        ga_key = f"{g}:{a}"
        if ga_key in seen:
            continue        # already have this artifact (nearest-wins)
        seen[ga_key] = v
        resolved.append(dep)

        pom_data = fetch_pom(g, a, v)
        for child in pom_data.get("direct", []):
            ck = f"{child['group_id']}:{child['artifact_id']}"
            if ck not in seen:
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

    # Parse the raw input into structured coords, then expand to direct transitives
    # via Maven Central POM fetch before the LLM sees the list.
    parsed_coords: list[dict] = []
    for line in dep_input.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            parsed_coords.append({
                "group_id": parts[0].strip(),
                "artifact_id": parts[1].strip(),
                "version": parts[2].strip(),
                "scope": "compile",
            })

    if parsed_coords:
        expanded_coords = _expand_maven_deps(parsed_coords)
        expanded_json = json.dumps(expanded_coords, indent=2)
        recon_desc = (
            f"Validate and confirm this pre-expanded dependency list "
            f"(direct inputs + their Maven transitive dependencies). "
            f"Return it as-is as a JSON array:\n\n{expanded_json}"
        )
    else:
        expanded_json = "[]"
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
        description="Compile findings into a report with severity, CVE ID, description, and fix.",
        expected_output="A structured vulnerability report with severity ratings and remediation steps.",
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
    has_url = payload.github_url and payload.github_url.strip()

    if not has_input and not has_url:
        raise HTTPException(
            status_code=400,
            detail="Provide 'github_url' (full repo scan) or 'input' (dependency coordinates).",
        )

    if has_url:
        scan_key, display_name = _scan_key_for_url(payload.github_url)
        scan_path, tmp_dir = resolve_repo_path(payload.github_url)
        try:
            try:
                report_text = await asyncio.to_thread(_run_full_scan, scan_path)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            build_system = ""
            m = re.search(r"build system.*?\*\*(\w+)\*\*", report_text, re.IGNORECASE)
            if m:
                build_system = m.group(1).lower()
            db_save_scan(scan_key, display_name, "url", build_system, report_text)
            return ScanResponse(result=report_text)
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    scan_key, display_name = _scan_key_for_deps(payload.input)
    result = await asyncio.to_thread(_run_dep_scan, payload.input)
    db_save_scan(scan_key, display_name, "dep", "", result)
    return ScanResponse(result=result)


@app.get("/history")
async def history(limit: int = 50):
    """Return recent scan summaries (no full report text)."""
    with _db_conn() as conn:
        rows = conn.execute(
            """SELECT id, scan_key, display_name, input_type, build_system,
                      total_deps, vuln_count, scanned_at
               FROM scans ORDER BY scanned_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.get("/history/{scan_id}")
async def history_detail(scan_id: int):
    """Return full report for a specific past scan."""
    with _db_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id=?", (scan_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(dict(row))


@app.delete("/history/{scan_id}", status_code=204)
async def history_delete(scan_id: int):
    """Delete a past scan record."""
    with _db_conn() as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))


@app.get("/health")
async def health():
    """Check API and LLM backend connectivity."""
    result: dict = {"status": "ok", "llm_vendor": LLM_VENDOR}

    if LLM_VENDOR == "google":
        google_key = bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
        result["google"] = {"api_key_set": google_key}
    else:
        ollama_ok = False
        models = []
        try:
            resp = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            resp.raise_for_status()
            models = [m["name"] for m in resp.json().get("models", [])]
            ollama_ok = True
        except Exception:
            pass
        result["ollama"] = {"reachable": ollama_ok, "url": OLLAMA_URL, "models": models}

    return result
