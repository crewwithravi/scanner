#!/usr/bin/env python3
"""
VulnHawk - Tool Validation
Run: python tests/test_tools.py (from project root)
"""

import json
import os
import sys

# Add app/ to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"))

from tools import DetectBuildSystemTool, ExtractDependenciesTool


def test_detect_build_system():
    print("=" * 50)
    print("TEST 1: Detect Build System")
    print("=" * 50)
    tool = DetectBuildSystemTool()

    result = tool._run("./sample_repo")
    print(f"  Sample repo detected as: {result}")
    assert result == "maven", f"Expected 'maven', got '{result}'"
    print("  PASSED\n")


def test_extract_dependencies():
    print("=" * 50)
    print("TEST 2: Extract Dependencies")
    print("=" * 50)
    tool = ExtractDependenciesTool()

    result = tool._run("./sample_repo", "maven")
    deps = json.loads(result)

    print(f"  Found {len(deps)} dependencies:")
    for d in deps:
        print(f"    {d['group_id']}:{d['artifact_id']}:{d['version']}")

    assert len(deps) >= 7, f"Expected at least 7 deps, got {len(deps)}"

    log4j = [d for d in deps if d["artifact_id"] == "log4j-core"]
    assert len(log4j) == 1, "log4j-core not found"
    assert log4j[0]["version"] == "2.14.1", f"log4j version mismatch: {log4j[0]['version']}"

    spring = [d for d in deps if d["artifact_id"] == "spring-core"]
    assert len(spring) == 1, "spring-core not found"
    assert spring[0]["version"] == "5.3.18", f"Spring version not resolved: {spring[0]['version']}"

    print("  PASSED\n")


def test_osv_api_connectivity():
    print("=" * 50)
    print("TEST 3: OSV API Connectivity")
    print("=" * 50)
    import requests

    try:
        response = requests.post(
            "https://api.osv.dev/v1/querybatch",
            json={
                "queries": [{
                    "package": {
                        "name": "org.apache.logging.log4j:log4j-core",
                        "ecosystem": "Maven",
                    },
                    "version": "2.14.1",
                }]
            },
            timeout=15,
        )
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("results", [{}])[0].get("vulns", [])
            print(f"  OSV API reachable. Found {len(vulns)} vulns for log4j 2.14.1")
            if vulns:
                print(f"  Sample IDs: {[v['id'] for v in vulns[:3]]}")
            print("  PASSED\n")
        else:
            print(f"  OSV API returned status {response.status_code}\n")
    except Exception as e:
        print(f"  OSV API not reachable: {e}\n")


def test_ollama_connectivity():
    print("=" * 50)
    print("TEST 4: Ollama Connectivity")
    print("=" * 50)
    from dotenv import load_dotenv
    import httpx

    load_dotenv()

    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://192.168.4.44:11434")
    try:
        resp = httpx.get(f"{ollama_url}/api/tags", timeout=5)
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        print(f"  Ollama reachable at {ollama_url}")
        print(f"  Available models: {models}")
        print("  PASSED\n")
    except Exception as e:
        print(f"  Ollama not reachable at {ollama_url}: {e}")
        print("  Make sure Ollama is running with OLLAMA_HOST=0.0.0.0\n")


if __name__ == "__main__":
    print("\nVulnHawk - Tool Validation\n")
    test_detect_build_system()
    test_extract_dependencies()
    test_osv_api_connectivity()
    test_ollama_connectivity()
    print("=" * 50)
    print("All tests done. Ready to scan.")
    print("=" * 50)
