"""
VulnHawk - CrewAI Agents
4-agent pipeline: Repo Scanner → Vulnerability Analyst → Upgrade Strategist → Report Generator
All powered by Ollama (remote GPU).
"""

import os
from crewai import Agent, LLM
from tools import (
    DetectBuildSystemTool,
    ExtractDependenciesTool,
    OSVVulnerabilityCheckTool,
    MavenCentralVersionLookupTool,
    SearchCodeUsageTool,
    FetchChangelogTool,
    ReadProjectDocsTool,
)

LLM_VENDOR = os.getenv("LLM_VENDOR", "ollama").strip().lower()

# Ollama settings
OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")

# Google Gemini settings
GOOGLE_MODEL = os.getenv("GOOGLE_MODEL", "gemini-2.0-flash")


def get_llm() -> LLM:
    """Return an LLM instance based on LLM_VENDOR env var ('ollama' or 'google')."""
    if LLM_VENDOR == "google":
        return LLM(
            model=f"gemini/{GOOGLE_MODEL}",
            temperature=0.2,
            timeout=600,
        )

    # Default: Ollama
    return LLM(
        model=f"ollama/{OLLAMA_MODEL}",
        base_url=OLLAMA_URL,
        temperature=0.2,
        timeout=600,
    )


# Backward-compatible alias
get_ollama_llm = get_llm


def create_agents():
    """Create and return all 4 agents for the vulnerability scanning crew."""
    llm = get_llm()

    repo_scanner = Agent(
        role="Repository Build System Analyst",
        goal=(
            "Analyze a Java/Kotlin repository to detect its build system (Maven or Gradle) "
            "and extract the complete dependency tree including transitive dependencies."
        ),
        backstory=(
            "You are an expert in Java/JVM build systems. You can identify whether a project "
            "uses Maven or Gradle by examining the repository structure. Once identified, you "
            "extract all dependencies with their exact versions. You always provide structured "
            "JSON output for downstream processing."
        ),
        tools=[DetectBuildSystemTool(), ExtractDependenciesTool()],
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

    vuln_analyst = Agent(
        role="Vulnerability Security Analyst",
        goal=(
            "Check every dependency from the extracted dependency list against the OSV "
            "(Open Source Vulnerabilities) database. Identify all known vulnerabilities, "
            "their severity, and available fixed versions."
        ),
        backstory=(
            "You are a cybersecurity specialist focused on software supply chain security. "
            "You systematically check every dependency against vulnerability databases. "
            "You prioritize vulnerabilities by severity (CRITICAL > HIGH > MEDIUM > LOW) "
            "and always note the specific CVE/GHSA identifiers."
        ),
        tools=[OSVVulnerabilityCheckTool()],
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

    upgrade_strategist = Agent(
        role="Dependency Upgrade Strategist",
        goal=(
            "For each vulnerable dependency, find the best safe UPGRADE version. "
            "NEVER recommend downgrades. Review actual source code usage to assess "
            "whether the upgrade will break existing API calls. "
            "Recommend the smallest version bump that fixes all known vulnerabilities."
        ),
        backstory=(
            "You are a senior software engineer who specializes in dependency management "
            "and migration. You ALWAYS recommend UPGRADING to a newer version that fixes "
            "the vulnerability — you NEVER recommend downgrading. You ALWAYS read the "
            "changelog and release notes before recommending an upgrade. You search the "
            "project's source code to see which APIs from the dependency are actually used, "
            "then fetch the changelog to check if those APIs changed in the target version. "
            "You also read the project's own documentation to verify if breaking changes "
            "actually affect this specific project. You understand semantic versioning: "
            "same-major upgrades are usually safe, cross-major upgrades need careful review."
        ),
        tools=[
            MavenCentralVersionLookupTool(),
            SearchCodeUsageTool(),
            FetchChangelogTool(),
            ReadProjectDocsTool(),
        ],
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

    report_generator = Agent(
        role="Security Report Generator",
        goal=(
            "Generate a clear, actionable vulnerability report summarizing all findings. "
            "Include: executive summary, list of vulnerable dependencies sorted by severity, "
            "recommended upgrade paths, and any risks or manual actions needed."
        ),
        backstory=(
            "You are a technical writer specializing in security reports. You create reports "
            "that are clear for both developers and management. You include actionable "
            "recommendations, prioritize by risk, and format output as clean Markdown."
        ),
        tools=[],
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

    return repo_scanner, vuln_analyst, upgrade_strategist, report_generator
