"""
VulnHawk - FastAPI Server
API-powered vulnerability scanner using CrewAI + Ollama.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000
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
from tools import OSVVulnerabilityCheckTool, DetectBuildSystemTool, ExtractDependenciesTool

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
                upgrade = cols[1].strip("` *_").strip()
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


def create_tasks(repo_scanner, vuln_analyst, upgrade_strategist, report_generator, repo_path: str):
    """Create the full 4-task pipeline for repo scanning."""

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
            "The previous task produced a JSON object with a 'dependencies' key.\n\n"
            "Steps:\n"
            "1. Find the 'dependencies' JSON array from the previous task.\n"
            "2. Pass that ENTIRE array to the 'Check OSV Vulnerabilities' tool.\n"
            "3. Return the tool's full JSON result as-is.\n\n"
            "IMPORTANT: The tool expects a JSON ARRAY of dependency objects. "
            "Pass all dependencies in a single call.\n\n"
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


def _run_full_scan(scan_path: str) -> str:
    """Synchronous full-repo scan — runs in a thread via asyncio.to_thread."""
    repo_scanner, vuln_analyst, upgrade_strategist, report_generator = create_agents()
    tasks = create_tasks(
        repo_scanner, vuln_analyst, upgrade_strategist, report_generator,
        scan_path,
    )
    crew = Crew(
        agents=[repo_scanner, vuln_analyst, upgrade_strategist, report_generator],
        tasks=tasks,
        process=Process.sequential,
        verbose=True,
    )
    result = crew.kickoff()
    report_text = clean_report(str(result))
    expected_build_system, expected_allowlist, expected_vuln_ids = _compute_vuln_expectations(scan_path)
    validate_report_dependencies(
        report_text,
        expected_build_system,
        expected_allowlist,
        expected_vuln_ids,
    )
    return report_text


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
