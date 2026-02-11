# VulnHawk

AI-powered dependency vulnerability scanner for Java/Kotlin repositories. Uses a 4-agent CrewAI pipeline backed by Google Gemini or Ollama to detect vulnerabilities, find safe upgrades, and generate actionable security reports.

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
  - [Docker (Recommended)](#docker-recommended)
  - [Local Installation](#local-installation)
- [Usage](#usage)
  - [REST API](#rest-api)
  - [CLI](#cli)
- [Configuration](#configuration)
- [Agent Pipeline](#agent-pipeline)
- [Tools](#tools)
- [Report Format](#report-format)
- [Project Structure](#project-structure)
- [Supported Build Systems](#supported-build-systems)

---

## How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
│  Agent 1:       │     │  Agent 2:        │     │  Agent 3:         │     │  Agent 4:        │
│  Repo Scanner   │────▶│  Vuln Analyst    │────▶│  Upgrade          │────▶│  Report          │
│                 │     │                  │     │  Strategist       │     │  Generator       │
│ - Detect Maven  │     │ - Query OSV API  │     │ - Find safe       │     │ - Markdown       │
│   or Gradle     │     │ - Get CVE details│     │   versions        │     │   report         │
│ - Extract deps  │     │ - Rank severity  │     │ - Check compat    │     │ - Action items   │
└─────────────────┘     └──────────────────┘     └───────────────────┘     └──────────────────┘
```

1. **Repo Scanner** detects the build system (Maven or Gradle) and extracts every dependency with its version.
2. **Vulnerability Analyst** batch-queries the [OSV](https://osv.dev) database and collects CVE/GHSA identifiers, severity ratings, and fix versions.
3. **Upgrade Strategist** looks up safe versions on Maven Central, fetches changelogs from GitHub, searches your source code for actual API usage, and assesses whether each upgrade is safe.
4. **Report Generator** compiles everything into a structured 10-section Markdown report.

---

## Architecture

VulnHawk has two entry points:

| Mode | Entry Point | Description |
|------|-------------|-------------|
| **REST API** | `app/main.py` | FastAPI server on port 8000 — accepts GitHub URLs or dependency coordinates |
| **CLI** | `main.py` | Command-line tool — accepts local paths or GitHub URLs |

Both modes run the same 4-agent pipeline and produce the same report format.

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

```bash
# Google Gemini (default)
LLM_VENDOR=google
GEMINI_API_KEY=your-key-here

# Or Ollama
# LLM_VENDOR=ollama
# OLLAMA_BASE_URL=http://your-gpu-server:11434
# OLLAMA_MODEL=llama3.1
```

#### 2. Build and run

```bash
# Google Gemini mode (no GPU needed)
docker compose up -d vulnhawk-api

# Ollama mode (NVIDIA GPU required)
docker compose --profile ollama up -d
```

#### 3. Verify

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "llm_vendor": "google",
  "google": { "api_key_set": true }
}
```

#### 4. Run a scan

```bash
# Scan a GitHub repository (full pipeline)
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/user/java-project"}'

# Quick scan from dependency coordinates
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"input": "org.apache.logging.log4j:log4j-core:2.14.1"}'
```

### Local Installation

#### Prerequisites

- Python 3.10+
- A Google Gemini API key ([free at aistudio.google.com](https://aistudio.google.com/apikey)) or an Ollama server

#### Install

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API key
```

#### Run the API server

```bash
cd app
uvicorn main:app --host 0.0.0.0 --port 8000
```

#### Run the CLI

```bash
python main.py https://github.com/user/java-project
python main.py /path/to/local/java/project
python main.py ./sample_repo
```

Reports are saved as `vulnerability_report_YYYYMMDD_HHMMSS.md` in the current directory.

---

## Usage

### REST API

#### `GET /health`

Returns API status and LLM backend connectivity.

```bash
curl http://localhost:8000/health
```

**Response (Google mode):**
```json
{
  "status": "ok",
  "llm_vendor": "google",
  "google": { "api_key_set": true }
}
```

**Response (Ollama mode):**
```json
{
  "status": "ok",
  "llm_vendor": "ollama",
  "ollama": {
    "reachable": true,
    "url": "http://ollama:11434",
    "models": ["llama3.1:latest", "qwen2.5-coder:32b"]
  }
}
```

#### `POST /scan`

Runs a vulnerability scan. Accepts two input types:

**Full repo scan** (clones the repo, runs all 4 agents):

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/user/repo"}'
```

**Quick dependency scan** (parses coordinates, checks OSV only):

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"input": "org.apache.logging.log4j:log4j-core:2.14.1, com.fasterxml.jackson.core:jackson-databind:2.13.0"}'
```

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `github_url` | string | One of these | GitHub repository URL to clone and scan |
| `input` | string | must be set | Comma-separated dependency coordinates (`group:artifact:version`) |

**Response:**
```json
{
  "result": "# Security Vulnerability Report\n\n## Executive Summary\n..."
}
```

### CLI

```bash
# Scan a local repo
python main.py /path/to/java/project

# Scan a GitHub repo (cloned to temp dir automatically)
python main.py https://github.com/user/repo

# Fast mode — skips LLM, generates report directly from tool output
VULNHAWK_FAST=1 python main.py /path/to/project
```

**Fast mode** (`VULNHAWK_FAST=1`) bypasses the LLM agents and builds the report programmatically from raw tool output. Useful for CI/CD pipelines where speed matters more than prose quality.

---

## Configuration

All configuration is done through environment variables (`.env` file).

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_VENDOR` | `ollama` | LLM backend: `google` or `ollama` |
| `GEMINI_API_KEY` | — | Google Gemini API key (required when `LLM_VENDOR=google`) |
| `GOOGLE_MODEL` | `gemini-2.0-flash` | Gemini model to use |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `llama3.1` | Ollama model name |
| `APP_PORT` | `8000` | Host port for the API (Docker only) |
| `VULNHAWK_FAST` | — | Set to `1` to enable fast/fallback mode (CLI only) |

**Recommended Gemini models:**

| Model | Trade-off |
|-------|-----------|
| `gemini-2.0-flash` | Fast, good for most scans |
| `gemini-2.5-flash` | Balanced speed and depth |
| `gemini-2.5-pro` | Most thorough analysis |

---

## Agent Pipeline

### Agent 1: Repository Build System Analyst

Detects whether the project uses Maven or Gradle and extracts the complete dependency list with exact versions.

**Tools:** Detect Build System, Extract Dependencies
**Output:** JSON with `build_system` and `dependencies` array

### Agent 2: Vulnerability Security Analyst

Batch-queries every dependency against the [OSV](https://osv.dev) vulnerability database. Collects CVE/GHSA identifiers, severity (CRITICAL/HIGH/MEDIUM/LOW), summaries, and fix versions.

**Tools:** Check OSV Vulnerabilities
**Output:** Full vulnerability report JSON

### Agent 3: Dependency Upgrade Strategist

For each vulnerable dependency:
1. Looks up available versions on Maven Central
2. Searches your source code for actual usage of the dependency's APIs
3. Fetches the changelog/release notes from GitHub
4. Reads project documentation to check if breaking changes apply
5. Recommends the smallest safe upgrade (never a downgrade)

**Tools:** Lookup Latest Safe Version, Search Code Usage, Fetch Changelog, Read Project Docs
**Output:** JSON array of upgrade recommendations with compatibility assessments

### Agent 4: Security Report Generator

Compiles all findings into a structured 10-section Markdown report with tables, severity rankings, and actionable next steps.

**Tools:** None (consumes output from the other three agents)
**Output:** Final Markdown report

---

## Tools

VulnHawk includes 7 custom CrewAI tools:

| Tool | Description | External API |
|------|-------------|--------------|
| **Detect Build System** | Checks for `pom.xml`, `build.gradle`, `gradlew`, etc. | None |
| **Extract Dependencies** | Parses Maven/Gradle build files or runs `mvn`/`gradle` commands | None |
| **Check OSV Vulnerabilities** | Batch-queries all dependencies against the OSV database | `api.osv.dev` (free, no key) |
| **Lookup Latest Safe Version** | Finds available versions and recommends the best upgrade | `search.maven.org` (free, no key) |
| **Search Code Usage** | Grep-like search for package imports across `.java`, `.kt`, `.scala`, `.groovy` files | None |
| **Fetch Changelog** | Maps Maven coordinates to GitHub repos and fetches release notes | GitHub API (unauthenticated) |
| **Read Project Docs** | Searches README, docs/, and config files for relevant terms | None |

**No Maven or Gradle installation required** for basic scanning — the tools parse build files directly. If Maven or Gradle IS installed in the environment, the tools use them for more accurate transitive dependency resolution.

---

## Report Format

Every scan produces a Markdown report with these 10 sections:

### 1. Executive Summary
Total vulnerabilities found and the most critical ones by name.

### 2. Build System
Whether the project uses Maven or Gradle.

### 3. Scan Statistics
Exact counts: total dependencies checked, vulnerable, safe.

### 4. Critical & High Vulnerabilities

| Dependency | Vuln ID | Severity | Summary | Fix Version |
| --- | --- | --- | --- | --- |
| org.apache.logging.log4j:log4j-core:2.14.1 | GHSA-7rjr-3q55-vv33 | CRITICAL | Log4Shell RCE | 2.17.0 |

### 5. Medium & Low Vulnerabilities
Same table format as above.

### 6. Upgrade Plan

| Dependency | Upgrade | Reason | Fix Version |
| --- | --- | --- | --- |
| org.apache.logging.log4j:log4j-core:2.14.1 | ...log4j-core:2.14.1 -> ...log4j-core:2.24.3 | Latest safe release fixing GHSA-7rjr-3q55-vv33 | 2.17.0 |

### 7. Compatibility Analysis

| Dependency | Upgrade | Breaking Changes | Project Affected | Safe to Upgrade |
| --- | --- | --- | --- | --- |
| org.apache.logging.log4j:log4j-core:2.14.1 | ...2.14.1 -> ...2.24.3 | None noted | NO | YES |

Based on changelog findings, source code usage, and project documentation.

### 8. Compatibility Warnings
Highlights any upgrades that need manual review.

### 9. Next Steps
Actionable recommendations (apply upgrades, run tests, review breaking changes).

### 10. Dependency Allowlist
A JSON array of all vulnerable dependencies for policy/tooling integration:
```
Dependency Allowlist: ["org.apache.logging.log4j:log4j-core:2.14.1"]
```

---

## Project Structure

```
scanner/
├── main.py                  # CLI entry point
├── requirements.txt         # Python dependencies (used by Docker)
├── Dockerfile               # Production container (non-root, healthcheck)
├── docker-compose.yml       # API service + optional Ollama GPU service
├── .env.example             # Configuration template
├── README.md
├── sample_repo/             # Test repo with known vulnerable deps
│   └── pom.xml
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI server (/scan, /health)
│   ├── agents.py            # 4 CrewAI agent definitions + LLM config
│   └── tools.py             # 7 custom CrewAI tools
└── tests/
    ├── __init__.py
    └── test_tools.py
```

---

## Supported Build Systems

| Build System | Detection | Dependency Extraction |
|-------------|-----------|----------------------|
| **Maven** | `pom.xml` | `mvn dependency:list` or direct XML parsing with property resolution (`${project.version}`, etc.) |
| **Gradle** | `build.gradle`, `build.gradle.kts`, `gradlew` | `gradle dependencies` or direct parsing of `implementation`, `api`, `compileOnly`, `runtimeOnly`, `testImplementation` blocks |

---

## Docker Details

### Container hardening

- Runs as non-root `vulnhawk` user
- Minimal `python:3.11-slim` base image
- Only `git` installed as system dependency
- Built-in healthcheck on `/health` endpoint

### Two deployment modes

**Google Gemini (default)** — no GPU needed:
```bash
docker compose up -d vulnhawk-api
```

**Ollama (self-hosted LLM)** — requires NVIDIA GPU:
```bash
docker compose --profile ollama up -d
```

The Ollama service stores models in a persistent `ollama_data` volume.

### Useful commands

```bash
# Rebuild after code changes
docker compose build

# View logs
docker compose logs -f vulnhawk-api

# Stop
docker compose down
```
