> **Disclosure:** VulnHawk is a personal learning project and experimental prototype, built to explore multi-agent AI pipelines, vulnerability data sources, and LLM-assisted security tooling. It is **not production software**. It comes with no warranty, no SLA, and no guarantee of accuracy or completeness. Do not use scan results as a substitute for professional security review. Use at your own risk.

---

# VulnHawk

AI-powered dependency vulnerability scanner for Java and Kotlin repositories. Combines a 4-agent [CrewAI](https://www.crewai.com/) pipeline with the [OSV](https://osv.dev) and [NVD](https://nvd.nist.gov) vulnerability databases and [Maven Central](https://search.maven.org) to detect CVEs, assess upgrade safety, detect BOM-managed dependencies, and generate structured Markdown security reports.

Supports Maven and Gradle. Works on public GitHub repositories or local paths. Deployable as a REST API (Docker or local) or a CLI tool.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
  - [Docker (Recommended)](#docker-recommended)
  - [Local Installation](#local-installation)
- [Usage](#usage)
  - [Web UI](#web-ui)
  - [REST API](#rest-api)
  - [CLI](#cli)
- [Scan History](#scan-history)
- [Fast Mode](#fast-mode)
- [BOM-Aware Upgrades](#bom-aware-upgrades)
- [Configuration](#configuration)
- [Agent Pipeline](#agent-pipeline)
- [Tools](#tools)
- [Report Format](#report-format)
- [Project Structure](#project-structure)
- [Supported Build Systems](#supported-build-systems)
- [Docker Details](#docker-details)
- [Known Limitations](#known-limitations)
- [Licence](#licence)

---

## How It Works

```
GitHub URL or local path
        │
        ▼
┌───────────────────┐
│  Agent 1:         │  Detects Maven/Gradle, runs mvn dependency:tree
│  Repo Scanner     │  or gradle dependencies to get the FULL
│                   │  transitive dependency tree (not just declared deps)
└────────┬──────────┘
         │  JSON: [{group_id, artifact_id, version, scope, depth}, ...]
         ▼
┌───────────────────┐
│  Agent 2:         │  Batch-queries OSV API for all deps (direct + transitive)
│  Vuln Analyst     │  NVD fallback for Apache Tomcat, Struts, Log4j
│                   │  Outputs CVE IDs, CVSS scores, affected ranges, fix versions
└────────┬──────────┘
         │  JSON: {vulnerabilities: [...], total_checked: N, vuln_count: M}
         ▼
┌───────────────────┐
│  Agent 3:         │  For each vuln:
│  Upgrade          │  1. BOM check — is this dep managed by Spring Boot BOM?
│  Strategist       │  2. Version lookup — smallest safe version on Maven Central
│                   │  3. Changelog review — breaking changes between versions
│                   │  4. Code search — which APIs from this dep are actually used
│                   │  5. Docs check — does the project rely on changed features
└────────┬──────────┘
         │  Upgrade plan with confidence scores
         ▼
┌───────────────────┐
│  Agent 4:         │  Compiles everything into a 10-section Markdown report
│  Report           │  Includes exact pom.xml / build.gradle lines to change
│  Generator        │  Saved to scan history database
└───────────────────┘
```

The entire pipeline runs in approximately 2–5 minutes for a typical Spring Boot project with 50–200 dependencies, depending on network speed and LLM response times.

---

## Architecture

VulnHawk has two entry points that share the same agent pipeline:

| Mode | Entry Point | Description |
|------|-------------|-------------|
| **REST API + Web UI** | `app/main.py` | FastAPI server on port 8000 — web interface, REST endpoints, scan history |
| **CLI** | `main.py` | Command-line tool — accepts local paths or GitHub URLs, writes `.md` report files |

Both modes run the same 4-agent CrewAI pipeline and produce identical report formats.

**LLM backends:**

| Backend | Setting | Notes |
|---------|---------|-------|
| Google Gemini | `LLM_VENDOR=google` | Default and recommended. Cloud API, no GPU required. Runs full LLM pipeline. |
| Ollama | `LLM_VENDOR=ollama` | Self-hosted, requires NVIDIA GPU. Automatically uses fast/deterministic mode (Ollama models do not reliably complete the multi-step report task). |

---

## Quick Start

### Docker (Recommended)

#### 1. Clone and configure

```bash
git clone https://github.com/your-org/vulnhawk.git
cd vulnhawk
cp .env.example .env
```

Edit `.env` and set your LLM credentials:

```env
# Google Gemini (recommended — no GPU needed)
LLM_VENDOR=google
GEMINI_API_KEY=your-key-here
GOOGLE_MODEL=gemini-2.0-flash

# Ollama (self-hosted, requires NVIDIA GPU)
# LLM_VENDOR=ollama
# OLLAMA_BASE_URL=http://ollama:11434
# OLLAMA_MODEL=llama3.1
```

Get a free Gemini API key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey).

#### 2. Build and start

```bash
# Interactive first-run setup (creates .env, builds image, starts containers)
./deploy.sh

# Or start directly if .env already exists
docker compose up -d vulnhawk-api

# Ollama mode (NVIDIA GPU required)
docker compose --profile ollama up -d
```

#### 3. Verify

```bash
curl http://localhost:8000/health
```

Expected:
```json
{
  "status": "ok",
  "llm_vendor": "google",
  "google": { "api_key_set": true }
}
```

#### 4. Open the web UI

Navigate to `http://localhost:8000` in your browser.

#### 5. Run your first scan via API

```bash
# Scan a GitHub repository
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/user/java-project"}'

# Quick scan from dependency coordinates
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"input": "org.apache.logging.log4j:log4j-core:2.14.1"}'
```

---

### Local Installation

#### Prerequisites

- Python 3.10 or later
- A Google Gemini API key **or** an Ollama server
- Java 17+ and Maven (optional — needed for full transitive dependency resolution; VulnHawk falls back to XML parsing if unavailable)

#### Install

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API key
```

#### Run the API server

```bash
cd app
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### Run the CLI

```bash
# Scan a local repository
python main.py /path/to/local/java/project

# Scan a GitHub repository (cloned automatically to a temp directory)
python main.py https://github.com/user/java-project

# Fast mode — skip LLM, generate report deterministically from tool output
VULNHAWK_FAST=1 python main.py /path/to/project
```

Reports are saved as `vulnerability_report_YYYYMMDD_HHMMSS.md` in the current directory.

---

## Usage

### Web UI

Open `http://localhost:8000` in your browser. The UI provides:

- **GitHub URL tab** — paste any public GitHub URL and click Scan
- **Dependency list tab** — paste Maven/Gradle coordinates directly (one per line, `group:artifact:version` format)
- **Live progress bar** — shows which agent is currently running
- **Rendered report** — severity badges, sortable tables, colour-coded vulnerability status
- **History panel** — click the clock icon in the top-right to browse, reload, or delete past scans

---

### REST API

All endpoints are available at `http://localhost:8000`. Interactive Swagger docs are at `/docs`.

---

#### `GET /health`

Returns API status and LLM backend connectivity. Use this to confirm the server is running and the LLM credentials are valid before triggering a scan.

```bash
curl http://localhost:8000/health
```

**Response — Google mode:**
```json
{
  "status": "ok",
  "llm_vendor": "google",
  "google": { "api_key_set": true }
}
```

**Response — Ollama mode:**
```json
{
  "status": "ok",
  "llm_vendor": "ollama",
  "ollama": {
    "reachable": true,
    "url": "http://ollama:11434",
    "models": ["llama3.1:latest"]
  }
}
```

---

#### `POST /scan`

Triggers a vulnerability scan. Accepts two input modes — provide exactly one.

**Request body:**

| Field | Type | Description |
|-------|------|-------------|
| `github_url` | string | Public GitHub repository URL to clone and scan. Supports `https://github.com/owner/repo` and `.git` URLs. |
| `input` | string | Raw dependency coordinates to scan without cloning a repo. Comma- or newline-separated `group:artifact:version` strings. |

**Full repo scan** (clones the repo, runs all 4 agents, resolves transitive deps):

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/spring-projects/spring-petclinic"}'
```

**Quick dependency scan** (skips cloning, checks OSV only, no code analysis):

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "input": "org.apache.logging.log4j:log4j-core:2.14.1\ncom.fasterxml.jackson.core:jackson-databind:2.13.0"
  }'
```

**Response:**
```json
{
  "result": "# Security Vulnerability Report\n\n## Executive Summary\n\n..."
}
```

The `result` field contains the full Markdown report. Scans are automatically saved to the history database.

---

#### `GET /history`

Returns a paginated list of past scan summaries ordered most-recent first. Does not include the full report text (use `GET /history/{id}` for that).

```bash
curl http://localhost:8000/history          # last 50 scans (default)
curl "http://localhost:8000/history?limit=10"
```

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | `50` | Maximum number of scans to return |

**Response:**
```json
[
  {
    "id": 7,
    "scan_key": "spring-projects/spring-petclinic",
    "display_name": "spring-petclinic",
    "input_type": "url",
    "build_system": "maven",
    "total_deps": 84,
    "vuln_count": 3,
    "scanned_at": "2026-02-28T14:32:11+00:00"
  },
  {
    "id": 6,
    "scan_key": "dep-list:a3f9c12b4d8e",
    "display_name": "Dep list (2 deps)",
    "input_type": "dep",
    "build_system": "",
    "total_deps": 2,
    "vuln_count": 2,
    "scanned_at": "2026-02-28T12:00:00+00:00"
  }
]
```

**Fields:**

| Field | Description |
|-------|-------------|
| `id` | Unique scan ID — use this in `GET /history/{id}` and `DELETE /history/{id}` |
| `scan_key` | Stable identifier: `owner/repo` for URL scans, `dep-list:<sha256-prefix>` for dependency list scans. Repeated scans of the same repo share the same `scan_key`. |
| `display_name` | Short human-readable name shown in the UI |
| `input_type` | `url` (GitHub repo scan) or `dep` (dependency list scan) |
| `build_system` | `maven`, `gradle`, or empty for dep-list scans |
| `total_deps` | Number of dependencies checked (parsed from report) |
| `vuln_count` | Number of vulnerable dependencies found |
| `scanned_at` | ISO 8601 UTC timestamp |

---

#### `GET /history/{id}`

Returns the full Markdown report for a specific past scan.

```bash
curl http://localhost:8000/history/7
```

**Response:**
```json
{
  "id": 7,
  "scan_key": "spring-projects/spring-petclinic",
  "display_name": "spring-petclinic",
  "input_type": "url",
  "build_system": "maven",
  "total_deps": 84,
  "vuln_count": 3,
  "report_md": "# Security Vulnerability Report\n\n...",
  "scanned_at": "2026-02-28T14:32:11+00:00"
}
```

Returns `404` if the scan ID does not exist.

---

#### `DELETE /history/{id}`

Removes a scan record from the history database.

```bash
curl -X DELETE http://localhost:8000/history/7
```

Returns `204 No Content` on success.

---

### CLI

The CLI entry point (`main.py` at the project root) runs the same pipeline without the web server. Results are written to a Markdown file in the current directory.

```bash
# Scan a local Maven or Gradle project
python main.py /path/to/java/project

# Scan a GitHub repository (shallow cloned to a temp dir, deleted after)
python main.py https://github.com/owner/repo

# Fast mode — skip the LLM, generate report from tool output directly
VULNHAWK_FAST=1 python main.py /path/to/project
```

Output file: `vulnerability_report_YYYYMMDD_HHMMSS.md`

---

## Scan History

Every completed scan is automatically saved to a SQLite database. The web UI exposes a **History** panel (clock icon, top-right of the header) showing:

- Repository name and scan key
- Vulnerability count (red badge) or "Clean" (green badge)
- Dependency count (blue badge) and build system
- Timestamp
- Click any row to instantly reload the full report without re-scanning
- Delete button (hover to reveal) to remove individual records

**OSV result caching:** The OSV + NVD vulnerability lookup for a given set of dependencies is cached in the same database for 24 hours. This means re-scanning the same project within that window skips the API calls entirely and goes straight to the LLM report generation phase.

**Database location:**

| Context | Default path | How to customise |
|---------|-------------|------------------|
| Local dev | `vulnhawk.db` in the project root | Set `VULNHAWK_DB=/path/to/file.db` |
| Docker | Ephemeral (lost on restart) | See [Persisting Scan History](#persisting-scan-history) |

The `scans` table schema:

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-increment primary key |
| `scan_key` | TEXT | `owner/repo` or `dep-list:<hash>` |
| `display_name` | TEXT | Short name for display |
| `input_type` | TEXT | `url` or `dep` |
| `build_system` | TEXT | `maven`, `gradle`, or empty |
| `total_deps` | INTEGER | Parsed from the report |
| `vuln_count` | INTEGER | Parsed from the report |
| `report_md` | TEXT | Full Markdown report |
| `scanned_at` | TEXT | ISO 8601 UTC timestamp |

---

## Fast Mode

VulnHawk has two report generation modes:

**LLM mode** (default with `LLM_VENDOR=google`): All 4 CrewAI agents run in sequence. The LLM reads the tool outputs and writes a prose report with nuanced upgrade reasoning, confidence scores, and detailed compatibility notes. The report is then validated against the actual vulnerability data — if validation fails, the system automatically falls back to deterministic mode.

**Deterministic (fast) mode**: Skips the LLM agents entirely. The report is generated directly and programmatically from the raw OSV/NVD tool output. This is faster and fully reproducible, but produces a more mechanical report.

Fast mode is activated automatically in two situations:
1. `VULNHAWK_FAST=1` is set explicitly
2. `LLM_VENDOR=ollama` — Ollama/local models do not reliably complete the complex multi-step report generation task, so fast mode is always used instead of wasting 10–15 minutes of inference time

In fast mode, the version lookup, changelog fetch, and code search tools still run — only the LLM narrative generation is skipped.

---

## BOM-Aware Upgrades

Many critical vulnerabilities in Spring Boot projects involve libraries that are **not directly declared in `pom.xml` or `build.gradle`** — they are version-managed by the Spring Boot BOM (`spring-boot-dependencies`). Examples:

- `org.apache.tomcat.embed:tomcat-embed-core` (embedded Tomcat)
- `com.fasterxml.jackson.core:jackson-databind`
- `io.netty:netty-all`
- `org.apache.logging.log4j:log4j-core`
- `ch.qos.logback:logback-classic`
- `org.yaml:snakeyaml`

If you bump these libraries **directly** in your build file when they are BOM-managed, you override the BOM and cause version conflicts and classpath inconsistencies. The correct fix is to bump the **Spring Boot parent version**, which automatically brings in the safe version of the managed dependency.

VulnHawk detects this automatically. For every vulnerable dependency, Agent 3 (Upgrade Strategist) first calls the **BOM Parent Resolver** tool, which checks a built-in map of Spring Boot BOM versions against embedded library versions (sourced from the official [Spring Boot dependency appendix](https://docs.spring.io/spring-boot/appendix/dependency-versions/)).

**Example report output for a BOM-managed dep:**

```
⚠ DO NOT bump tomcat-embed-core directly — it is managed by the Spring Boot BOM.

FIX: Upgrade spring-boot 3.2.5 → 3.3.10
     This automatically brings tomcat-embed-core 10.1.30 (>= the safe version 10.1.20).

In pom.xml:       <spring-boot.version>3.3.10</spring-boot.version>
In build.gradle:  id 'org.springframework.boot' version '3.3.10'
```

Spring Boot BOM versions tracked: 2.6.14, 2.7.8, 2.7.18, 3.2.12, 3.3.10, 3.4.5, 3.5.8, 3.5.11.

---

## Configuration

All configuration is via environment variables, typically set in a `.env` file at the project root.

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_VENDOR` | `ollama` | LLM backend: `google` (Gemini) or `ollama` (local) |
| `GEMINI_API_KEY` | — | Google Gemini API key. Required when `LLM_VENDOR=google`. Free at [aistudio.google.com](https://aistudio.google.com/apikey) |
| `GOOGLE_MODEL` | `gemini-2.0-flash` | Gemini model ID to use |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Base URL of the Ollama server |
| `OLLAMA_MODEL` | `llama3.1` | Ollama model name (e.g. `llama3.1`, `qwen2.5-coder:32b`) |
| `APP_PORT` | `8000` | Host port exposed by Docker |
| `VULNHAWK_FAST` | — | Set to `1` to force fast/deterministic mode (skips LLM agents) |
| `VULNHAWK_DB` | `./vulnhawk.db` | Path to the SQLite database for scan history and OSV cache |

**Recommended Gemini models:**

| Model | Notes |
|-------|-------|
| `gemini-2.0-flash` | Fast, accurate, free tier available. Recommended default. |
| `gemini-2.5-flash` | Balanced speed and depth. Better reasoning on complex upgrade decisions. |
| `gemini-2.5-pro` | Most thorough analysis. Slower and uses more quota. |

---

## Agent Pipeline

### Agent 1: Repository Build System Analyst

**Role:** Detect the build system and extract a complete dependency tree including all transitive dependencies.

**Tools:** Detect Build System, Extract Dependencies

**What it does:**
1. Looks for `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, `gradlew` to identify Maven or Gradle
2. Runs `mvn dependency:tree -DoutputType=text` or `gradle dependencies --configuration runtimeClasspath` to get the full tree
3. Falls back to direct XML/Groovy parsing if Maven/Gradle is not installed
4. For Gradle projects without a wrapper, falls back to BFS transitive expansion via Maven Central POM fetching
5. Resolves Spring Boot BOM version declarations in `build.gradle` to fill in unversioned dependencies

**Output:** A JSON array where every entry includes `group_id`, `artifact_id`, `version`, `scope`, and `depth` (0 = direct dependency, 1+ = transitive).

**Why transitive deps matter:** The Log4Shell vulnerability (Log4j 2.x, CVE-2021-44228) affected thousands of projects that did not know they were using Log4j because it was pulled in 3–5 levels deep as a transitive dependency of other frameworks.

---

### Agent 2: Vulnerability Security Analyst

**Role:** Check every dependency — direct and transitive — against the OSV and NVD vulnerability databases.

**Tools:** Check OSV Vulnerabilities (with NVD fallback)

**What it does:**
1. Batch-queries the [OSV API](https://api.osv.dev/v1/querybatch) for all dependencies in a single HTTP request (batches of 1,000)
2. For each dependency that returns no OSV results, checks whether it falls into a known OSV blind spot (Apache Tomcat, Struts, Log4j) and queries NVD as a fallback
3. For each hit, fetches detailed vulnerability information: CVE/GHSA ID, CVSS score, severity (CRITICAL/HIGH/MEDIUM/LOW), affected version range, and the minimum fixed version
4. Returns a structured JSON report with a full vulnerabilities list plus counts

**Output:** JSON with `total_dependencies_checked`, `vulnerable_count`, `safe_count`, and a `vulnerabilities` array.

**NVD fallback:** OSV tracks Apache Tomcat only via Git commit ranges, not Maven package names — so `org.apache.tomcat.embed:*` queries always return empty from OSV. VulnHawk detects this and queries NVD directly for these packages, parsing CPE version ranges and description text to determine if the specific version is affected.

---

### Agent 3: Dependency Upgrade Strategist

**Role:** For each vulnerable dependency, determine the safest and smallest upgrade path.

**Tools:** BOM Parent Resolver, Lookup Latest Safe Version, Fetch Changelog, Search Code Usage, Read Project Docs

**What it does (in order for each vulnerable dep):**

1. **BOM check** — calls the BOM Parent Resolver to determine if the dep is Spring Boot BOM-managed. If yes, recommends bumping the parent instead and does not look for a direct version bump.
2. **Version lookup** — queries Maven Central for all available versions and finds the smallest version that is >= the minimum safe version. Labels each candidate as UPGRADE or DOWNGRADE (preventing accidental downgrades).
3. **Changelog review** — maps the Maven coordinates to the corresponding GitHub repository, fetches the release notes for the relevant version range, and identifies breaking API changes. Outputs a `confidence_score` (0–100).
4. **Code impact check** — searches `.java`, `.kt`, `.scala`, and `.groovy` source files for imports and usage of the vulnerable package. Cross-references with the breaking changes from step 3.
5. **Docs check** — reads `README.md`, `docs/`, and config files to verify whether the project relies on any features that changed in the upgrade.

**Output:** An upgrade recommendation per dependency including the target version, whether it is BOM-managed, the exact `pom.xml`/`build.gradle` line to change, confidence score, and any breaking changes to be aware of.

---

### Agent 4: Security Report Generator

**Role:** Compile all findings into a structured, actionable 10-section Markdown report.

**Tools:** None (consumes output from the other three agents)

**What it does:**
- Writes each vulnerability with its CVE/GHSA ID, CVSS score, severity, whether it is a direct or transitive dependency (with depth), and whether it is BOM-managed
- For every upgrade recommendation, provides the exact line to change in the build file
- Includes a confidence score for each upgrade
- Highlights any BOM-managed dependencies prominently to prevent developers from making the common mistake of bumping them directly
- Produces a `Dependency Allowlist` JSON array at the end of the report for policy tooling integration

The LLM output is validated against the actual OSV data after generation. If the report is missing any discovered vulnerabilities or contains invalid upgrade entries, VulnHawk falls back to the deterministic report builder automatically.

---

## Tools

VulnHawk includes 8 custom CrewAI tools:

| Tool | Class | External APIs | Description |
|------|-------|--------------|-------------|
| **Detect Build System** | `DetectBuildSystemTool` | None | Walks the repo root (up to 2 levels deep) looking for `pom.xml`, `build.gradle`, `gradlew`, etc. Returns `maven`, `gradle`, or `unknown`. |
| **Extract Dependencies** | `ExtractDependenciesTool` | Maven Central (POM fetching) | Runs `mvn dependency:tree` or `gradle dependencies` for full transitive resolution. Falls back to XML/Groovy parsing + BFS POM expansion via Maven Central if no build tool is installed. Resolves Spring Boot BOM version declarations. Skips `test`, `provided`, and `system` scopes. |
| **Check OSV Vulnerabilities** | `OSVVulnerabilityCheckTool` | `api.osv.dev`, `services.nvd.nist.gov` | Batch-queries OSV for all dependencies. NVD fallback for Apache Tomcat, Struts, and Log4j (which OSV only tracks via Git commits, not Maven coordinates). Cached in SQLite for 24 hours keyed on a SHA-256 of the dep list. Rate-limited to 5 NVD requests per 30 seconds. |
| **BOM Parent Resolver** | `BOMParentResolverTool` | None | Checks whether a vulnerable dependency is version-managed by the Spring Boot BOM. If yes, returns the minimum Spring Boot version to bump to and the exact build file line to change. Covers 8 Spring Boot releases from 2.6.x to 3.5.x. |
| **Lookup Latest Safe Version** | `MavenCentralVersionLookupTool` | `search.maven.org` | Queries Maven Central for all available versions of a dependency. Finds the smallest version >= the minimum safe version. Explicitly labels candidates as UPGRADE or DOWNGRADE to prevent accidental regressions. |
| **Fetch Changelog** | `FetchChangelogTool` | GitHub API (unauthenticated) | Maps Maven `group:artifact` coordinates to the corresponding GitHub repository and fetches release notes for the version range being upgraded. Returns a `confidence_score` (0–100) on upgrade safety based on breaking changes found. Includes a special fallback URL pattern for Apache Tomcat changelogs. |
| **Search Code Usage** | `SearchCodeUsageTool` | None | Grep-like search across `.java`, `.kt`, `.scala`, and `.groovy` source files for import statements and API usage of a given package. Used to cross-reference breaking changes in changelogs against actual usage in the project. |
| **Read Project Docs** | `ReadProjectDocsTool` | None | Searches `README.md`, `docs/`, and common config files for terms relevant to a dependency upgrade. Helps verify whether the project uses features that changed in the target version. |

**No Maven or Gradle installation is required** for basic scanning — the tools parse build files directly. If Maven or Gradle is installed in the environment (which it is in the Docker image), the tools use them for more accurate full transitive dependency resolution.

---

## Report Format

Every scan produces a Markdown report with 10 sections:

### 1. Executive Summary

A 2–4 sentence overview of findings: total vulnerabilities found, the most critical ones by name, and the overall upgrade risk level.

### 2. Build System

States whether the project uses Maven or Gradle and the version detected.

### 3. Scan Statistics

Exact counts in a summary table:

| Metric | Value |
|--------|-------|
| Total Dependencies Checked | 84 |
| Vulnerable | 3 |
| Safe | 81 |
| Critical | 1 |
| High | 1 |
| Medium | 1 |

### 4. Critical & High Vulnerabilities

A table with one row per vulnerability:

| Dependency | Type | Vuln ID | CVSS | Severity | Summary | Fix Version |
|------------|------|---------|------|----------|---------|-------------|
| `org.apache.tomcat.embed:tomcat-embed-core:9.0.50` | TRANSITIVE (depth=2) | CVE-2023-28708 | 7.5 | HIGH | Session fixation via `JSESSIONID` cookie without `Secure` flag | 9.0.52 |

The **Type** column shows whether the dependency is directly declared (`DIRECT`) or pulled in transitively (`TRANSITIVE (depth=N)`), where depth 1 means pulled in by a direct dependency, depth 2 means two levels deep, and so on.

### 5. Medium & Low Vulnerabilities

Same table format as section 4.

### 6. Upgrade Plan

A table of concrete version bumps to make:

| Dependency | Upgrade | Via Parent | Reason | Confidence |
|------------|---------|-----------|--------|-----------|
| `org.apache.tomcat.embed:tomcat-embed-core:9.0.50` | `spring-boot 3.2.5 → 3.3.10` | YES — bump spring-boot | BOM-managed; direct bump would cause classpath conflicts | 92% |
| `com.example:some-lib:1.2.0` | `some-lib:1.2.0 → 1.3.4` | NO | Fixes CVE-2023-XXXXX; patch release, no breaking changes | 97% |

The **Via Parent** column explicitly flags BOM-managed dependencies. These rows show a parent version bump rather than a direct version string.

### 7. Compatibility Analysis

| Dependency | Upgrade | Breaking Changes | Project Affected | Safe to Upgrade | BOM Managed |
|------------|---------|-----------------|-----------------|----------------|-------------|
| `org.apache.tomcat.embed:tomcat-embed-core:9.0.50` | `spring-boot → 3.3.10` | None in this version range | NO | YES | YES |
| `com.example:some-lib:1.2.0` | `1.2.0 → 1.3.4` | `SomeClass.oldMethod()` removed | NO (unused in project) | YES | NO |

The **Project Affected** column is based on the actual code search results — if the removed API is not imported anywhere in the project, it is marked `NO`.

### 8. Compatibility Warnings

Free-text warnings for any upgrades that require manual review — major version bumps, removed APIs that are used, or low confidence scores.

### 9. Next Steps

A numbered checklist of actions, for example:
1. Update Spring Boot version in `pom.xml` to 3.3.10
2. Run `mvn dependency:tree` to verify the new Tomcat version
3. Run the test suite
4. Review the `SomeClass` deprecation warning (no breaking impact found but worth verifying)

### 10. Dependency Allowlist

A JSON array of all vulnerable dependencies in `group:artifact:version` format, intended for policy and tooling integration:

```
Dependency Allowlist: ["org.apache.tomcat.embed:tomcat-embed-core:9.0.50", "com.example:some-lib:1.2.0"]
```

This line is machine-parseable and used internally by VulnHawk to validate that the report covers all discovered vulnerabilities.

---

## Project Structure

```
scanner/
├── main.py                    # CLI entry point (same pipeline, writes .md files)
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Production container (non-root user, healthcheck, Java 17 + Maven)
├── docker-compose.yml         # API service + optional Ollama GPU service
├── deploy.sh                  # Linux one-command deploy/update/restart script
├── .env.example               # Configuration template
├── README.md
├── vulnhawk.db                # SQLite — scan history + OSV cache (auto-created on startup)
├── sample_repo/               # Test Maven project with known vulnerable dependencies
│   └── pom.xml
├── app/
│   ├── __init__.py
│   ├── main.py                # FastAPI server — /scan, /history, /health endpoints
│   │                          # SQLite DB init, OSV cache, scan key logic, clean_report()
│   ├── agents.py              # 4 CrewAI agent definitions with roles, goals, backstories
│   ├── tools.py               # 8 custom CrewAI tools (see Tools section above)
│   └── static/
│       ├── index.html         # Single-page web UI (dark theme, Tailwind CSS)
│       └── app.js             # UI logic: scan form, SSE progress, report rendering,
│                              # severity badges, dep table, history panel
└── tests/
    ├── __init__.py
    └── test_tools.py          # Unit tests for individual tools
```

---

## Supported Build Systems

### Maven

| Feature | Detail |
|---------|--------|
| Detection | Presence of `pom.xml` in the repository root |
| Full transitive resolution | `mvn dependency:tree -DoutputType=text --batch-mode -q` (timeout: 180s) |
| Fallback (no Maven) | Direct XML parsing of `pom.xml` with `${property}` placeholder resolution |
| Property resolution | `<properties>` block resolved before version substitution |
| Scope filtering | `test`, `provided`, and `system` scopes excluded |
| BOM imports | Resolved recursively through parent POM chain |

### Gradle

| Feature | Detail |
|---------|--------|
| Detection | `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, or `gradlew` |
| Full transitive resolution | `./gradlew dependencies --configuration runtimeClasspath --no-daemon` (falls back to `compileClasspath`) |
| Fallback (no Gradle) | Direct parsing of `build.gradle` dependency blocks + BFS POM expansion via Maven Central |
| Configurations extracted | `implementation`, `api`, `compileOnly`, `runtimeOnly`, `testImplementation` |
| Spring Boot BOM | Detects `id 'org.springframework.boot' version 'X.Y.Z'` in `build.gradle` and fetches the BOM to resolve unversioned dependencies |
| JAVA_HOME | Auto-detected from common Linux JDK paths if not set in environment |

---

## Docker Details

### Container hardening

- Runs as non-root `vulnhawk` user
- `python:3.11-slim` base image
- System packages: `git`, `default-jdk-headless` (Java 17), `maven` — only what is needed for dependency resolution
- Gradle downloads itself on first use via the project wrapper (`gradlew`); its cache is stored at `/home/vulnhawk/.gradle`
- Maven local repository at `/home/vulnhawk/.m2`
- Built-in `HEALTHCHECK` on the `/health` endpoint (every 30s, 5s timeout, 3 retries)

### Two deployment modes

**Google Gemini (default)** — no GPU needed:
```bash
docker compose up -d vulnhawk-api
```

**Ollama (self-hosted LLM)** — requires NVIDIA GPU:
```bash
docker compose --profile ollama up -d
```

The Ollama service stores downloaded models in a persistent `ollama_data` named volume. On first run with a new model, the model download can take several minutes.

### Persisting scan history

By default, the SQLite database is created inside the container at the project root and is lost when the container is removed. To persist scan history and OSV cache across restarts, mount a Docker volume and point `VULNHAWK_DB` at it.

Add to your `docker-compose.yml`:

```yaml
services:
  vulnhawk-api:
    volumes:
      - vulnhawk_data:/data
    environment:
      - VULNHAWK_DB=/data/vulnhawk.db

volumes:
  vulnhawk_data:
  ollama_data:
```

Or set `VULNHAWK_DB=/data/vulnhawk.db` in your `.env` file and add the volume mount separately.

### Using `deploy.sh`

The `deploy.sh` script wraps `docker compose` for common operations on Linux:

```bash
./deploy.sh            # First-run interactive setup: creates .env, builds image, starts containers
./deploy.sh --update   # Rebuild image and do a rolling restart (no downtime)
./deploy.sh --restart  # Restart containers without rebuilding
./deploy.sh --stop     # Stop and remove containers
./deploy.sh --logs     # Tail live logs (last 100 lines)
./deploy.sh --status   # Show container status + /health response
```

On first run, the script interactively prompts for LLM backend choice, API key, model name, and port. It then creates a `.env` file with `chmod 600` permissions.

### Other useful commands

```bash
# Rebuild after code changes
docker compose build

# Tail logs
docker compose logs -f vulnhawk-api

# Run a one-off scan from the command line inside the container
docker exec vulnhawk-api-1 python main.py https://github.com/owner/repo

# Stop everything
docker compose down
```

---

## Known Limitations

### OSV blind spot: Apache Tomcat, Struts, Log4j

The OSV database tracks Apache Tomcat vulnerabilities via Git commit ranges rather than Maven package coordinates. This means a query for `org.apache.tomcat.embed:tomcat-embed-core:9.0.50` against the OSV API returns no results even if that version is vulnerable.

VulnHawk handles this automatically with an NVD fallback:

1. Detects known blind-spot group IDs (`org.apache.tomcat.embed`, `org.apache.tomcat`, `org.apache.struts`, `org.apache.logging.log4j`, `org.apache.log4j`)
2. Queries NVD for all CVEs matching the product keyword (paginated, rate-limited to 5 requests per 30 seconds)
3. Checks CPE version ranges in each CVE to determine if the specific version is affected
4. For older CVEs with no CPE configurations, falls back to parsing "from X through Y" version patterns in the CVE description text

NVD CVE data for each product is cached in memory for the duration of a single scan session to avoid redundant API calls.

### Transitive resolution without Maven/Gradle

If neither Maven nor Gradle is installed, VulnHawk falls back to parsing `pom.xml` or `build.gradle` directly and expanding transitive dependencies by fetching POM files from Maven Central. This is slower (network-bound) and slightly less accurate than running the build tool directly, particularly for projects that use complex version management or custom repositories. The Docker image includes both Java 17 and Maven to avoid this limitation.

### Private repositories

Cloning requires the repository to be publicly accessible via HTTPS. Private GitHub repositories are not supported — the `git clone` call does not include any authentication credentials.

### Gradle multi-project builds

The current implementation scans the root project's dependency tree. Sub-projects in a Gradle multi-project build are not individually scanned.

---

## Licence

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

*VulnHawk is a sample/beta learning project. Vulnerability data is sourced from OSV and NVD — always verify critical findings independently before taking action.*
