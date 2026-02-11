"""
VulnHawk - FastAPI Server
API-powered vulnerability scanner using CrewAI + Ollama.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000
"""

import os
import re
import json
import shutil
import subprocess
import tempfile
import httpx
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
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
        dep = cols[0].strip("` ").strip()
        if not dep or dep.lower() == "dependency":
            continue
        deps.add(dep)
        if current_section not in sections:
            sections[current_section] = set()
        sections[current_section].add(dep)
        if current_section not in vuln_ids:
            vuln_ids[current_section] = set()
        if current_section == "upgrade plan":
            if len(cols) >= 2:
                upgrade = cols[1].strip("` ").strip()
                if upgrade and upgrade.lower() != "upgrade":
                    upgrades.add(upgrade)
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

    tmp_dir = None

    if has_url:
        scan_path, tmp_dir = resolve_repo_path(payload.github_url)
        # Full repo scan
        try:
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
            try:
                expected_build_system, expected_allowlist, expected_vuln_ids = _compute_vuln_expectations(scan_path)
                validate_report_dependencies(
                    report_text,
                    expected_build_system,
                    expected_allowlist,
                    expected_vuln_ids,
                )
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            return ScanResponse(result=report_text)
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    # Quick dependency list scan
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

    recon_task = Task(
        description=f"Parse this dependency list into JSON with group_id, artifact_id, version:\n\n{payload.input}",
        expected_output="A JSON array of packages with group_id, artifact_id, and version.",
        agent=recon_agent,
    )

    vuln_task = Task(
        description="Use the 'Check OSV Vulnerabilities' tool with the JSON array from the previous step.",
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

    result = crew.kickoff()
    return ScanResponse(result=str(result))


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
