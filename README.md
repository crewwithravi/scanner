# Vulnerability Scanner - CrewAI + Google Gemini

A multi-agent AI-powered tool that scans Java/Kotlin repositories for dependency vulnerabilities using CrewAI and Google Gemini.

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

**Pipeline:**
1. **Repo Scanner** → Detects build system (Maven/Gradle), extracts all dependencies
2. **Vulnerability Analyst** → Queries OSV batch API for every dependency
3. **Upgrade Strategist** → Finds safe versions on Maven Central, uses Gemini to assess compatibility
4. **Report Generator** → Produces a clean Markdown report with actionable recommendations

## Setup

### 1. Prerequisites
- Python 3.10 - 3.13
- A Google Gemini API key (free at https://aistudio.google.com/apikey)

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Key

```bash
# Option A: Create .env file
cp .env.example .env
# Edit .env and add your key

# Option B: Export directly
export GEMINI_API_KEY=your_key_here
```

## Usage

### Scan a Local Repository

```bash
python main.py /path/to/your/java/project
```

### Scan a GitHub Repository

```bash
python main.py https://github.com/user/some-java-project
```

The repo will be cloned to a temporary directory, scanned, and automatically cleaned up.

### Test with Sample Repo (includes known vulnerabilities)

```bash
python main.py ./sample_repo
```

### Output
- The scan prints progress to the console
- A Markdown report is saved as `vulnerability_report_YYYYMMDD_HHMMSS.md`

## Project Structure

```
scanner/
├── main.py               # Entry point - run this
├── requirements.txt      # Python dependencies
├── .env.example          # Template for API key
├── README.md
├── sample_repo/           # Test repo with known vulnerable deps
│   └── pom.xml
├── vuln_scanner/          # Core package
│   ├── __init__.py
│   ├── agents.py          # CrewAI agent definitions (4 agents)
│   ├── tasks.py           # Task definitions for each agent
│   └── tools.py           # Custom tools (build detection, dep extraction, OSV, Maven Central)
└── tests/                 # Test suite
    ├── __init__.py
    └── test_tools.py      # Tool validation tests
```

## Supported Build Systems
- **Maven** (pom.xml) - Full parsing with property resolution
- **Gradle** (build.gradle / build.gradle.kts) - Direct parsing and gradle wrapper support

## Tools Used
| Tool | Purpose |
|------|---------|
| OSV API (`api.osv.dev`) | Vulnerability database lookup (free, no API key needed) |
| Maven Central API | Version lookup for upgrade recommendations |
| Google Gemini | LLM for compatibility analysis and report generation |
| CrewAI | Multi-agent orchestration framework |

## Customization

### Change the Gemini Model
In `agents.py`, modify the `get_gemini_llm()` function:

```python
return LLM(
    model="gemini/gemini-2.5-pro",  # Use Pro for deeper analysis
    api_key=api_key,
    temperature=0.2,
)
```

### Available Gemini models:
- `gemini/gemini-2.0-flash` (default - fast and capable)
- `gemini/gemini-2.5-pro` (more thorough analysis)
- `gemini/gemini-2.5-flash` (balanced)

## Sample Output

```
============================================================
  VULNERABILITY SCANNER
  Repository: /home/user/sample_repo
  Started:    2026-02-07 10:30:00
============================================================

[1/4] Creating AI agents...
[2/4] Defining tasks...
[3/4] Assembling crew...
[4/4] Running vulnerability scan...

... agent logs ...

============================================================
  SCAN COMPLETE
  Report saved to: vulnerability_report_20260207_103045.md
============================================================
```

## Notes
- **No Maven/Gradle installation required** for basic scanning - the tool can parse build files directly
- If Maven or Gradle IS installed, the tool will use them for more accurate transitive dependency resolution
- OSV API is free and requires no API key
- The Gemini compatibility analysis is advisory - always test upgrades in your CI/CD pipeline
