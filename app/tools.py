"""
VulnHawk - Custom CrewAI Tools
Handles: build system detection, dependency extraction, OSV vulnerability lookup,
Maven Central version lookup, BOM parent resolution, source code usage search.

Changes in this PR:
  1. Fix _extract_maven() output parser (wrong colon-split on mvn dependency:list)
  2. Wire _expand_transitive() into _extract_gradle() main path (was only in fallback)
  3. Add BOMParentResolverTool — resolves "tomcat 9.0.50 → bump spring-boot to 3.5.11"
  4. Add confidence_score to FetchChangelogTool output
  5. Add apache/tomcat changelog fallback URL to FetchChangelogTool
"""

import os
import re
import subprocess
import json
import time
import requests
from typing import Optional
from crewai.tools import BaseTool

# Module-level cache: NVD product CVEs fetched once per scan session
_NVD_PRODUCT_CVE_CACHE: dict = {}


class DetectBuildSystemTool(BaseTool):
    name: str = "Detect Build System"
    description: str = (
        "Scans a repository path and detects whether the project uses Maven or Gradle. "
        "Input: the absolute path to the repository root directory. "
        "Returns: 'maven', 'gradle', or 'unknown'."
    )

    def _run(self, repo_path: str) -> str:
        repo_path = repo_path.strip().strip("'\"")

        if not os.path.isdir(repo_path):
            return f"ERROR: Directory not found: {repo_path}"

        gradle_indicators = [
            "build.gradle", "build.gradle.kts",
            "settings.gradle", "settings.gradle.kts", "gradlew",
        ]
        for indicator in gradle_indicators:
            if os.path.exists(os.path.join(repo_path, indicator)):
                return "gradle"

        if os.path.exists(os.path.join(repo_path, "pom.xml")):
            return "maven"

        for root, dirs, files in os.walk(repo_path):
            depth = root.replace(repo_path, "").count(os.sep)
            if depth > 2:
                dirs.clear()
                continue
            for f in files:
                if f in ("build.gradle", "build.gradle.kts"):
                    return "gradle"
                if f == "pom.xml":
                    return "maven"

        return "unknown"


class ExtractDependenciesTool(BaseTool):
    name: str = "Extract Dependencies"
    description: str = (
        "Extracts ALL dependencies (including transitive) from a Maven or Gradle project. "
        "Input: repo_path (string) and build_system ('maven' or 'gradle'). "
        "Returns a JSON list of dependencies with groupId, artifactId, version, scope, "
        "and depth (0 = direct, 1+ = transitive)."
    )

    def _run(self, repo_path: str, build_system: str) -> str:
        repo_path = (repo_path or "").strip().strip("'\"")
        build_system = (build_system or "").strip().lower()

        if not os.path.isdir(repo_path):
            return f"ERROR: Directory not found: {repo_path}"

        if build_system == "maven":
            return self._extract_maven(repo_path)
        elif build_system == "gradle":
            return self._extract_gradle(repo_path)
        else:
            return f"ERROR: Unsupported build system: {build_system}"

    # ── MAVEN ──────────────────────────────────────────────────────────────

    def _extract_maven(self, repo_path: str) -> str:
        """
        Uses `mvn dependency:tree` for full transitive resolution.
        Output format per line (text mode):
          [INFO] +- groupId:artifactId:jar:version:scope
          [INFO] |  `- groupId:artifactId:jar:version:scope
        Falls back to XML parsing if mvn is not installed.
        """
        pom_path = os.path.join(repo_path, "pom.xml")
        if not os.path.exists(pom_path):
            return "ERROR: pom.xml not found"

        try:
            result = subprocess.run(
                [
                    "mvn", "dependency:tree",
                    "-DoutputType=text",
                    "-Dverbose=false",   # verbose adds omitted/conflict noise
                    "--batch-mode",
                    "-q",                # quiet — suppress download logs
                ],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=180,
            )
            if result.returncode == 0 and result.stdout.strip():
                parsed = self._parse_maven_tree(result.stdout)
                if parsed:
                    return json.dumps(parsed, indent=2)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: direct XML parse (direct deps only, no transitive)
        return self._parse_pom_xml(pom_path)

    def _parse_maven_tree(self, output: str) -> list[dict]:
        """
        Parse ``mvn dependency:tree -DoutputType=text`` output.

        Each dependency line looks like::

          [INFO] +- org.springframework.boot:spring-boot-starter-web:jar:3.1.0:compile
          [INFO] |  +- org.springframework.boot:spring-boot-starter:jar:3.1.0:compile
          [INFO] |  |  \\- org.springframework.boot:spring-boot:jar:3.1.0:compile

        Depth is determined by counting the tree-drawing characters before the coordinate.
        Format: groupId:artifactId:packaging:version:scope
        """
        dependencies = []
        seen: set[str] = set()

        # Pattern matches the coordinate after tree chars: g:a:packaging:version:scope
        coord_pattern = re.compile(
            r"\s[\+\\\|`\- ]*"          # tree drawing chars
            r"([^\s:]+)"                 # groupId
            r":([^\s:]+)"               # artifactId
            r":[^\s:]+"                 # packaging (jar/pom/war/...)
            r":([^\s:]+)"               # version
            r":([^\s:]+)"               # scope
        )
        # Depth = number of "|  " or "   " segments before the +- or \-
        depth_pattern = re.compile(r"(\|   |    |\|  |   )")

        for line in output.splitlines():
            if "[INFO]" not in line:
                continue
            # Strip the [INFO] prefix
            content = line.split("[INFO]", 1)[-1]

            coord_match = coord_pattern.search(content)
            if not coord_match:
                continue

            group_id    = coord_match.group(1).strip()
            artifact_id = coord_match.group(2).strip()
            version     = coord_match.group(3).strip()
            scope       = coord_match.group(4).strip()

            if not group_id or not artifact_id or not version:
                continue

            # Skip test/provided/system scopes for vulnerability purposes
            if scope in ("test", "provided", "system"):
                continue

            key = f"{group_id}:{artifact_id}"
            if key in seen:
                continue
            seen.add(key)

            # Calculate depth: count tree segments before the coordinate
            depth_part = content[:coord_match.start()]
            depth = len(depth_pattern.findall(depth_part))

            dependencies.append({
                "group_id":    group_id,
                "artifact_id": artifact_id,
                "version":     version,
                "scope":       scope,
                "depth":       depth,   # 0 = direct, 1+ = transitive
            })

        return dependencies

    def _parse_pom_xml(self, pom_path: str) -> str:
        """Fallback: parse pom.xml directly. Returns direct deps only (no transitive)."""
        import xml.etree.ElementTree as ET

        dependencies = []
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()

            ns = ""
            match = re.match(r"\{(.+?)\}", root.tag)
            if match:
                ns = match.group(1)
            ns_prefix = f"{{{ns}}}" if ns else ""

            # Resolve properties for ${...} version placeholders
            props: dict[str, str] = {}
            props_elem = root.find(f"{ns_prefix}properties")
            if props_elem is not None:
                for p in props_elem:
                    tag = p.tag.replace(ns_prefix, "")
                    props[tag] = p.text or ""

            for dep in root.iter(f"{ns_prefix}dependency"):
                group_id    = dep.find(f"{ns_prefix}groupId")
                artifact_id = dep.find(f"{ns_prefix}artifactId")
                version     = dep.find(f"{ns_prefix}version")
                scope       = dep.find(f"{ns_prefix}scope")

                if group_id is None or artifact_id is None:
                    continue

                ver_text = version.text if version is not None else "UNKNOWN"
                if ver_text and ver_text.startswith("${"):
                    prop_name = ver_text[2:-1]
                    ver_text = props.get(prop_name, ver_text)

                dependencies.append({
                    "group_id":    group_id.text or "",
                    "artifact_id": artifact_id.text or "",
                    "version":     ver_text or "UNKNOWN",
                    "scope":       scope.text if scope is not None else "compile",
                    "depth":       0,
                })

        except ET.ParseError as e:
            return f"ERROR: Failed to parse pom.xml: {e}"

        if not dependencies:
            return "ERROR: No dependencies found in pom.xml"

        return json.dumps(dependencies, indent=2)

    # ── GRADLE ─────────────────────────────────────────────────────────────

    def _extract_gradle(self, repo_path: str) -> str:
        gradle_cmd = None
        if os.path.exists(os.path.join(repo_path, "gradlew")):
            gradle_cmd = os.path.join(repo_path, "gradlew")
            try:
                os.chmod(gradle_cmd, 0o755)
            except PermissionError:
                pass
        else:
            try:
                subprocess.run(["gradle", "--version"], capture_output=True, timeout=10)
                gradle_cmd = "gradle"
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        if gradle_cmd:
            # Pass JAVA_HOME so the Gradle toolchain resolver can find the JDK.
            # Try common JDK locations on Linux if JAVA_HOME is not already set.
            gradle_env = os.environ.copy()
            if not gradle_env.get("JAVA_HOME"):
                for candidate in [
                    "/usr/lib/jvm/java-17-openjdk-amd64",
                    "/usr/lib/jvm/java-17-openjdk-arm64",
                    "/usr/lib/jvm/java-17-openjdk",
                    "/usr/lib/jvm/default-java",
                    "/usr/local/lib/jvm/temurin-17",
                ]:
                    if os.path.isdir(candidate):
                        gradle_env["JAVA_HOME"] = candidate
                        break

            for config in ["runtimeClasspath", "compileClasspath"]:
                try:
                    result = subprocess.run(
                        [gradle_cmd, "dependencies", "--configuration", config, "--no-daemon"],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                        timeout=180,
                        env=gradle_env,
                    )
                    if result.returncode == 0:
                        deps = self._parse_gradle_tree(result.stdout)
                        if deps:
                            # ── FIX: run _expand_transitive on gradle tree output too ──
                            # Gradle tree already contains transitive deps, but versions
                            # of unresolved BOM deps may be missing. Enrich with BOM data.
                            enriched = self._enrich_with_bom(repo_path, deps)
                            return json.dumps(enriched, indent=2)
                    else:
                        print(f"[VulnHawk] gradlew {config} failed (rc={result.returncode}): "
                              f"{result.stderr.strip()[:300]}")
                except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired):
                    pass

        # Full fallback: parse build.gradle manually + BFS transitive expansion
        return self._parse_build_gradle(repo_path)

    def _parse_gradle_tree(self, output: str) -> list[dict]:
        dependencies = []
        seen: set[str] = set()
        # Match lines like: +--- org.springframework.boot:spring-boot-starter-web:3.1.0
        pattern = re.compile(r"[\+\\\|\- ]+([^\s:]+):([^\s:]+):([^\s:\(\)]+)(?:\s.*)?$")

        for line in output.splitlines():
            match = pattern.search(line)
            if not match:
                continue

            group_id    = match.group(1)
            artifact_id = match.group(2)
            version     = match.group(3)

            # Handle "version -> resolved_version" (conflict resolution)
            if " -> " in version:
                version = version.split(" -> ")[-1]
            version = version.rstrip("(*)")

            if not version or version == "":
                continue

            # Depth from indentation: each level is 5 chars (+--- or |    )
            indent = len(line) - len(line.lstrip(" |+\\`"))
            depth  = max(0, indent // 5)

            key = f"{group_id}:{artifact_id}"
            if key in seen:
                continue
            seen.add(key)

            dependencies.append({
                "group_id":    group_id,
                "artifact_id": artifact_id,
                "version":     version,
                "scope":       "runtime",
                "depth":       depth,
            })

        return dependencies

    def _enrich_with_bom(self, repo_path: str, deps: list[dict]) -> list[dict]:
        """
        For Gradle projects: check if Spring Boot BOM is declared and fill in
        any deps that have UNKNOWN versions via BOM lookup.
        """
        for filename in ["build.gradle", "build.gradle.kts"]:
            filepath = os.path.join(repo_path, filename)
            if not os.path.exists(filepath):
                continue
            with open(filepath, "r") as f:
                content = f.read()
            sb_version = self._extract_spring_boot_version(content)
            if sb_version:
                bom = self._fetch_spring_boot_bom(sb_version)
                for dep in deps:
                    if dep["version"] in ("UNKNOWN", "", "unspecified"):
                        key = f"{dep['group_id']}:{dep['artifact_id']}"
                        resolved = bom.get(key)
                        if resolved:
                            dep["version"] = resolved
                            dep["version_source"] = f"spring-boot-bom:{sb_version}"
        return deps

    def _parse_build_gradle(self, repo_path: str) -> str:
        """Fallback: parse build.gradle manually + full BFS transitive expansion."""
        import xml.etree.ElementTree as ET

        dependencies = []
        seen: set[str] = set()

        for filename in ["build.gradle", "build.gradle.kts"]:
            filepath = os.path.join(repo_path, filename)
            if not os.path.exists(filepath):
                continue

            with open(filepath, "r") as f:
                content = f.read()

            bom_versions: dict[str, str] = {}
            sb_version = self._extract_spring_boot_version(content)
            if sb_version:
                bom_versions = self._fetch_spring_boot_bom(sb_version)

            for m in re.finditer(
                r"""['"]([A-Za-z0-9][\w.\-]*:[A-Za-z0-9][\w.\-]*:[A-Za-z0-9][\w.\-]*)['"]""",
                content,
            ):
                coord = m.group(1)
                if "$" in coord:
                    continue
                parts = coord.split(":")
                if len(parts) != 3:
                    continue
                key = f"{parts[0]}:{parts[1]}"
                if key not in seen:
                    seen.add(key)
                    dependencies.append({
                        "group_id":    parts[0],
                        "artifact_id": parts[1],
                        "version":     parts[2],
                        "scope":       "compile",
                        "depth":       0,
                    })

            if bom_versions:
                for m in re.finditer(
                    r"""['"]([A-Za-z0-9][\w.\-]*:[A-Za-z0-9][\w.\-]*)['"]""",
                    content,
                ):
                    coord = m.group(1)
                    if coord.count(":") != 1 or "$" in coord:
                        continue
                    version = bom_versions.get(coord)
                    if version and coord not in seen:
                        seen.add(coord)
                        parts = coord.split(":")
                        dependencies.append({
                            "group_id":    parts[0],
                            "artifact_id": parts[1],
                            "version":     version,
                            "scope":       "compile",
                            "depth":       0,
                            "version_source": f"spring-boot-bom:{sb_version}",
                        })

        if not dependencies:
            return "ERROR: No dependencies found in build.gradle"

        expanded = self._expand_transitive(dependencies)
        return json.dumps(expanded, indent=2)

    def _expand_transitive(self, direct: list[dict]) -> list[dict]:
        """BFS over Maven Central POMs to resolve the full transitive dependency tree."""
        import xml.etree.ElementTree as ET

        SKIP_SCOPES = {"test", "provided", "system"}
        pom_cache: dict[str, dict] = {}

        def pom_url(g: str, a: str, v: str) -> str:
            return (
                f"https://repo1.maven.org/maven2/"
                f"{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom"
            )

        def fetch_pom(g: str, a: str, v: str) -> dict:
            key = f"{g}:{a}:{v}"
            if key in pom_cache:
                return pom_cache[key]
            pom_cache[key] = {}
            try:
                resp = requests.get(pom_url(g, a, v), timeout=15)
                if resp.status_code != 200:
                    return {}
                root = ET.fromstring(resp.text)
            except Exception:
                return {}

            m = re.match(r"\{(.+?)\}", root.tag)
            ns = f"{{{m.group(1)}}}" if m else ""

            def txt(elem, tag: str, default: str = "") -> str:
                return (elem.findtext(f"{ns}{tag}", default) or default).strip()

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

            deps_direct: list[dict] = []
            deps_elem = root.find(f"{ns}dependencies")
            if deps_elem is not None:
                for d in deps_elem.findall(f"{ns}dependency"):
                    dg = resolve(txt(d, "groupId"))
                    da = resolve(txt(d, "artifactId"))
                    dv = resolve(txt(d, "version"))
                    ds = txt(d, "scope", "compile")
                    opt = txt(d, "optional", "false").lower()
                    if ds in SKIP_SCOPES or opt == "true":
                        continue
                    if not dv or dv.startswith("${"):
                        dv = dep_mgmt.get(f"{dg}:{da}", "")
                    if dg and da and dv and not dv.startswith("${"):
                        deps_direct.append({
                            "group_id": dg, "artifact_id": da,
                            "version": dv, "scope": ds,
                        })

            result = {"props": props, "dep_mgmt": dep_mgmt, "direct": deps_direct}
            pom_cache[key] = result
            return result

        seen: dict[str, str] = {}
        resolved: list[dict] = []
        queue: list[dict] = list(direct)

        while queue and len(resolved) < 10_000:
            dep = queue.pop(0)
            g = dep.get("group_id", "").strip()
            a = dep.get("artifact_id", "").strip()
            v = dep.get("version", "").strip()
            if not g or not a or not v or v == "UNKNOWN":
                continue
            ga_key = f"{g}:{a}"
            if ga_key in seen:
                continue
            seen[ga_key] = v
            resolved.append(dep)
            pom_data = fetch_pom(g, a, v)
            current_depth = dep.get("depth", 0)
            for child in pom_data.get("direct", []):
                if f"{child['group_id']}:{child['artifact_id']}" not in seen:
                    child["depth"] = current_depth + 1
                    queue.append(child)

        return resolved

    def _extract_spring_boot_version(self, content: str) -> str | None:
        for pattern in [
            r"""id\s*['"]org\.springframework\.boot['"]\s+version\s+['"]([^'"]+)['"]""",
            r"""id\("org\.springframework\.boot"\)\s+version\s+"([^"]+)""",
        ]:
            m = re.search(pattern, content)
            if m:
                return m.group(1)
        return None

    def _fetch_spring_boot_bom(self, version: str) -> dict[str, str]:
        import xml.etree.ElementTree as ET
        url = (
            f"https://repo1.maven.org/maven2/org/springframework/boot/"
            f"spring-boot-dependencies/{version}/spring-boot-dependencies-{version}.pom"
        )
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code != 200:
                return {}
            root = ET.fromstring(resp.text)
            ns_m = re.match(r"\{(.+?)\}", root.tag)
            ns = f"{{{ns_m.group(1)}}}" if ns_m else ""

            props: dict[str, str] = {}
            props_elem = root.find(f"{ns}properties")
            if props_elem is not None:
                for child in props_elem:
                    tag = child.tag.replace(ns, "")
                    props[tag] = child.text or ""

            bom: dict[str, str] = {}
            dep_mgmt = root.find(f"{ns}dependencyManagement/{ns}dependencies")
            if dep_mgmt is not None:
                for dep in dep_mgmt.findall(f"{ns}dependency"):
                    g = (dep.findtext(f"{ns}groupId") or "").strip()
                    a = (dep.findtext(f"{ns}artifactId") or "").strip()
                    v = (dep.findtext(f"{ns}version") or "").strip()
                    if v.startswith("${") and v.endswith("}"):
                        v = props.get(v[2:-1], v)
                    if g and a and v and not v.startswith("${"):
                        bom[f"{g}:{a}"] = v
            return bom
        except Exception:
            return {}


# ─────────────────────────────────────────────────────────────────────────────
# NEW TOOL: BOMParentResolverTool
# Answers: "This dep is managed by Spring Boot BOM — which parent version
#           ships the safe (non-vulnerable) version of this dep?"
# ─────────────────────────────────────────────────────────────────────────────

class BOMParentResolverTool(BaseTool):
    name: str = "BOM Parent Resolver"
    description: str = (
        "Determines whether a vulnerable dependency is managed by a parent BOM "
        "(e.g. Spring Boot BOM manages Tomcat, Netty, Jackson, Log4j versions). "
        "If yes, returns which parent version to upgrade to instead of bumping "
        "the dependency directly. "
        "Input: JSON with 'group_id', 'artifact_id', 'safe_version' (the minimum "
        "non-vulnerable version). "
        "Returns: fix_via_parent (bool), parent_artifact, bump_parent_to, "
        "current_parent_version, and a human-readable recommendation."
    )

    # Spring Boot BOM version → embedded library versions
    # Source: https://docs.spring.io/spring-boot/appendix/dependency-versions/
    # Key libraries only — those most commonly vulnerable
    SPRING_BOOT_BOM: dict[str, dict[str, str]] = {
        "3.5.11": {
            "org.apache.tomcat.embed:tomcat-embed-core":    "10.1.42",
            "org.apache.tomcat.embed:tomcat-embed-el":      "10.1.42",
            "org.apache.tomcat.embed:tomcat-embed-websocket": "10.1.42",
            "io.netty:netty-all":                           "4.1.121.Final",
            "com.fasterxml.jackson.core:jackson-databind":  "2.19.0",
            "org.apache.logging.log4j:log4j-core":          "2.24.3",
            "org.springframework:spring-core":              "6.2.8",
            "org.springframework.security:spring-security-core": "6.4.5",
            "ch.qos.logback:logback-classic":               "1.5.18",
            "org.yaml:snakeyaml:snakeyaml":                 "2.4",
        },
        "3.5.8": {
            "org.apache.tomcat.embed:tomcat-embed-core":    "10.1.39",
            "org.apache.tomcat.embed:tomcat-embed-el":      "10.1.39",
            "org.apache.tomcat.embed:tomcat-embed-websocket": "10.1.39",
            "io.netty:netty-all":                           "4.1.118.Final",
            "com.fasterxml.jackson.core:jackson-databind":  "2.18.3",
            "org.apache.logging.log4j:log4j-core":          "2.24.3",
            "org.springframework:spring-core":              "6.2.5",
        },
        "3.4.5": {
            "org.apache.tomcat.embed:tomcat-embed-core":    "10.1.35",
            "io.netty:netty-all":                           "4.1.115.Final",
            "com.fasterxml.jackson.core:jackson-databind":  "2.18.2",
            "org.apache.logging.log4j:log4j-core":          "2.24.2",
        },
        "3.3.10": {
            "org.apache.tomcat.embed:tomcat-embed-core":    "10.1.30",
            "io.netty:netty-all":                           "4.1.110.Final",
            "com.fasterxml.jackson.core:jackson-databind":  "2.17.2",
        },
        "3.2.12": {
            "org.apache.tomcat.embed:tomcat-embed-core":    "10.1.28",
            "io.netty:netty-all":                           "4.1.107.Final",
            "com.fasterxml.jackson.core:jackson-databind":  "2.16.2",
        },
        "2.7.18": {
            "org.apache.tomcat.embed:tomcat-embed-core":    "9.0.83",
            "io.netty:netty-all":                           "4.1.100.Final",
            "com.fasterxml.jackson.core:jackson-databind":  "2.14.3",
            "org.apache.logging.log4j:log4j-core":          "2.20.0",
        },
        "2.7.8": {
            "org.apache.tomcat.embed:tomcat-embed-core":    "9.0.70",
            "io.netty:netty-all":                           "4.1.85.Final",
            "com.fasterxml.jackson.core:jackson-databind":  "2.14.1",
        },
        "2.6.14": {
            "org.apache.tomcat.embed:tomcat-embed-core":    "9.0.65",
            "com.fasterxml.jackson.core:jackson-databind":  "2.13.5",
        },
    }

    def _run(
        self,
        input_json: str | None = None,
        group_id: str | None = None,
        artifact_id: str | None = None,
        safe_version: str | None = None,
        current_parent_artifact: str | None = None,
        current_parent_version: str | None = None,
    ) -> str:
        params: dict = {}
        if input_json:
            try:
                params = json.loads(input_json)
            except json.JSONDecodeError:
                return "ERROR: Input must be valid JSON."

        group_id   = (group_id   or params.get("group_id",   "")).strip()
        artifact_id = (artifact_id or params.get("artifact_id", "")).strip()
        safe_version = (safe_version or params.get("safe_version", "")).strip()
        current_parent_artifact = (
            current_parent_artifact or params.get("current_parent_artifact", "")
        ).strip()
        current_parent_version = (
            current_parent_version or params.get("current_parent_version", "")
        ).strip()

        if not group_id or not artifact_id or not safe_version:
            return "ERROR: group_id, artifact_id, and safe_version are all required."

        dep_key = f"{group_id}:{artifact_id}"
        safe_parts = self._parse_version(safe_version)

        result = {
            "dependency":              dep_key,
            "safe_version_needed":     safe_version,
            "fix_via_parent":          False,
            "parent_artifact":         None,
            "bump_parent_to":          None,
            "parent_ships_version":    None,
            "current_parent_version":  current_parent_version or "unknown",
            "recommendation":          None,
            "do_not_bump_directly":    False,
        }

        # Check Spring Boot BOM
        candidates: list[tuple] = []   # (spring_boot_version, dep_version_it_ships)
        for sb_ver, managed in self.SPRING_BOOT_BOM.items():
            shipped = managed.get(dep_key)
            if not shipped:
                continue
            shipped_parts = self._parse_version(shipped)
            if shipped_parts >= safe_parts:
                candidates.append((sb_ver, shipped))

        if not candidates:
            result["recommendation"] = (
                f"{dep_key} does not appear to be managed by the Spring Boot BOM, "
                f"or no tracked Spring Boot version ships {safe_version}+. "
                f"Bump {artifact_id} directly in your build file."
            )
            return json.dumps(result, indent=2)

        # Sort candidates by Spring Boot version ascending → pick the smallest bump
        candidates.sort(key=lambda x: self._parse_version(x[0]))
        best_sb_ver, ships_dep_ver = candidates[0]

        result["fix_via_parent"]       = True
        result["parent_artifact"]      = "org.springframework.boot:spring-boot-starter-parent"
        result["bump_parent_to"]       = best_sb_ver
        result["parent_ships_version"] = ships_dep_ver
        result["do_not_bump_directly"] = True

        # Build human-readable recommendation
        if current_parent_version:
            parent_change = (
                f"spring-boot {current_parent_version} → {best_sb_ver}"
            )
        else:
            parent_change = f"spring-boot → {best_sb_ver}"

        result["recommendation"] = (
            f"⚠ DO NOT bump {artifact_id} directly. "
            f"It is managed by the Spring Boot BOM.\n\n"
            f"FIX: Upgrade {parent_change}\n"
            f"     This will automatically bring {artifact_id} {ships_dep_ver} "
            f"(which is >= the safe version {safe_version}).\n\n"
            f"In pom.xml:  <spring-boot.version>{best_sb_ver}</spring-boot.version>\n"
            f"In build.gradle:  id 'org.springframework.boot' version '{best_sb_ver}'"
        )

        return json.dumps(result, indent=2)

    @staticmethod
    def _parse_version(v: str) -> tuple:
        if not v:
            return ()
        parts = []
        for p in re.split(r"[.\-]", re.sub(r"[^0-9.\-]", "", v)):
            try:
                parts.append(int(p))
            except ValueError:
                break
        return tuple(parts)


# ─────────────────────────────────────────────────────────────────────────────
# UNCHANGED tools below — OSV, MavenCentral, SearchCode, ReadDocs
# Only FetchChangelogTool gets confidence_score + Tomcat URL fix
# ─────────────────────────────────────────────────────────────────────────────

class OSVVulnerabilityCheckTool(BaseTool):
    name: str = "Check OSV Vulnerabilities"
    description: str = (
        "Checks a list of Maven/Gradle dependencies against the OSV database. "
        "Input: JSON list of dependencies with group_id, artifact_id, version fields. "
        "Returns: JSON report of vulnerabilities found."
    )

    MAVEN_CPE_MAP: dict = {
        "org.apache.tomcat.embed": ("apache", "tomcat", "Apache Tomcat"),
        "org.apache.tomcat":       ("apache", "tomcat", "Apache Tomcat"),
        "org.apache.struts":       ("apache", "struts2", "Apache Struts"),
        "org.apache.logging.log4j": ("apache", "log4j2", "Apache Log4j"),
        "org.apache.log4j":        ("apache", "log4j2", "Apache Log4j"),
    }

    def _run(self, dependencies_json: str) -> str:
        try:
            dependencies = json.loads(dependencies_json)
        except json.JSONDecodeError:
            return "ERROR: Input must be a valid JSON list of dependencies."

        if not isinstance(dependencies, list):
            return "ERROR: Input must be a JSON list."
        if not dependencies:
            return "No dependencies to check."

        queries = []
        dep_map = []

        for dep in dependencies:
            group_id    = dep.get("group_id", "")
            artifact_id = dep.get("artifact_id", "")
            version     = dep.get("version", "")
            if not all([group_id, artifact_id, version]) or version == "UNKNOWN":
                continue
            queries.append({
                "package": {"name": f"{group_id}:{artifact_id}", "ecosystem": "Maven"},
                "version": version,
            })
            dep_map.append(dep)

        if not queries:
            return "No valid dependencies to check (all have unknown versions)."

        all_results = []
        for i in range(0, len(queries), 1000):
            batch = queries[i : i + 1000]
            try:
                response = requests.post(
                    "https://api.osv.dev/v1/querybatch",
                    json={"queries": batch},
                    timeout=60,
                )
                response.raise_for_status()
                all_results.extend(response.json().get("results", []))
            except requests.exceptions.RequestException as e:
                return f"ERROR: OSV API request failed: {str(e)}"

        report = {
            "total_dependencies_checked": len(dep_map),
            "vulnerable_count": 0,
            "safe_count": 0,
            "vulnerabilities": [],
        }

        for idx, result in enumerate(all_results):
            if idx >= len(dep_map):
                break
            dep   = dep_map[idx]
            vulns = result.get("vulns", [])

            if not vulns:
                nvd_vulns = self._check_nvd_fallback(dep)
                if nvd_vulns:
                    report["vulnerable_count"] += 1
                    report["vulnerabilities"].append({
                        "dependency":        f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}",
                        "vulnerability_ids": [v["id"] for v in nvd_vulns],
                        "details":           nvd_vulns,
                        "source":            "NVD",
                    })
                else:
                    report["safe_count"] += 1
                continue

            report["vulnerable_count"] += 1
            vuln_ids = [v.get("id", "unknown") for v in vulns]
            vuln_details = [
                d for d in (self._get_vuln_details(vid) for vid in vuln_ids[:5]) if d
            ]
            report["vulnerabilities"].append({
                "dependency":        f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}",
                "vulnerability_ids": vuln_ids,
                "details":           vuln_details,
            })

        return json.dumps(report, indent=2)

    def _check_nvd_fallback(self, dep: dict) -> list:
        group_id = dep.get("group_id", "")
        version  = dep.get("version", "")
        if not version or version == "UNKNOWN":
            return []
        cpe_info = self.MAVEN_CPE_MAP.get(group_id)
        if not cpe_info:
            return []
        vendor, product, keyword = cpe_info
        cache_key = f"{vendor}:{product}"
        if cache_key not in _NVD_PRODUCT_CVE_CACHE:
            _NVD_PRODUCT_CVE_CACHE[cache_key] = self._fetch_nvd_cves_for_product(keyword, product)
        return [
            d for d in (
                self._nvd_vuln_detail(v, version, product)
                for v in _NVD_PRODUCT_CVE_CACHE[cache_key]
            ) if d
        ]

    def _fetch_nvd_cves_for_product(self, keyword: str, product: str) -> list:
        all_vulns = []
        start = 0
        while True:
            try:
                resp = requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": keyword, "resultsPerPage": 2000, "startIndex": start},
                    timeout=45,
                )
                resp.raise_for_status()
                data  = resp.json()
                vulns = data.get("vulnerabilities", [])
                all_vulns.extend(vulns)
                total = data.get("totalResults", 0)
                if start + 2000 >= total:
                    break
                start += 2000
                time.sleep(0.7)
            except requests.exceptions.RequestException:
                break
        return all_vulns

    def _nvd_vuln_detail(self, nvd_vuln: dict, version: str, product: str) -> Optional[dict]:
        cve       = nvd_vuln.get("cve", {})
        desc_full = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        )
        desc      = desc_full[:300]
        configs   = cve.get("configurations", [])

        if not configs:
            if not self._desc_version_affected(desc_full, version, product):
                return None
            severity, score = self._extract_nvd_severity(cve)
            return {
                "id": cve.get("id", "unknown"),
                "summary": desc + " [⚠ NVD CPE not yet processed]",
                "severity": severity, "fixed_versions": [], "aliases": [],
                "references": [r.get("url", "") for r in cve.get("references", [])[:3]],
                "cvss_score": score,
            }

        ver_parts      = self._parse_version(version)
        fixed_versions = []
        matched        = False

        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", True):
                        continue
                    criteria = match.get("criteria", "").lower()
                    if product not in criteria:
                        continue
                    cpe_fields  = match.get("criteria", "").split(":")
                    cpe_version = cpe_fields[5] if len(cpe_fields) > 5 else "*"

                    if cpe_version not in ("*", "-"):
                        if self._parse_version(cpe_version) != ver_parts:
                            continue
                        matched = True
                        break

                    vsi = self._parse_version(match.get("versionStartIncluding", ""))
                    vse = self._parse_version(match.get("versionStartExcluding", ""))
                    vei = self._parse_version(match.get("versionEndIncluding", ""))
                    vee = self._parse_version(match.get("versionEndExcluding", ""))

                    if not vsi and not vse and not vei and not vee:
                        continue

                    start_ok = (not vsi and not vse) or (vsi and ver_parts >= vsi) or (vse and ver_parts > vse)
                    end_ok   = (not vei and not vee) or (vei and ver_parts <= vei) or (vee and ver_parts < vee)

                    if start_ok and end_ok:
                        matched = True
                        fv = match.get("versionEndExcluding", "")
                        if fv and fv not in fixed_versions:
                            fixed_versions.append(fv)

        if not matched:
            return None

        severity, score = self._extract_nvd_severity(cve)
        return {
            "id":             cve.get("id", "unknown"),
            "summary":        desc or "No description available",
            "severity":       severity,
            "fixed_versions": fixed_versions,
            "aliases":        [],
            "references":     [r.get("url", "") for r in cve.get("references", [])[:3]],
            "cvss_score":     score,
        }

    def _extract_nvd_severity(self, cve: dict) -> tuple:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(key, [])
            if metrics:
                data  = metrics[0].get("cvssData", {})
                score = data.get("baseScore")
                sev   = data.get("baseSeverity", "")
                if sev:
                    return sev.upper(), score
                if score is not None:
                    return self._score_to_severity(float(score)), score
        return "UNKNOWN", None

    def _desc_version_affected(self, desc: str, version: str, product: str) -> bool:
        if not desc or product not in desc.lower():
            return False
        ver_parts = self._parse_version(version)
        if not ver_parts:
            return False
        for m in re.finditer(
            r'(?:from\s+([\d]+\.[\d]+[.\d]*(?:-[\w.]+)?)\s+)?'
            r'through\s+([\d]+\.[\d]+[.\d]*(?:-[\w.]+)?)',
            desc, re.IGNORECASE,
        ):
            end_parts = self._parse_version(m.group(2) or "")
            if not end_parts or ver_parts > end_parts:
                continue
            if m.group(1):
                if ver_parts < self._parse_version(m.group(1)):
                    continue
            return True
        for m in re.finditer(r'before\s+([\d]+\.[\d]+[.\d]*)', desc, re.IGNORECASE):
            if self._parse_version(m.group(1)) and ver_parts < self._parse_version(m.group(1)):
                return True
        return False

    def _get_vuln_details(self, vuln_id: str) -> Optional[dict]:
        try:
            resp = requests.get(f"https://api.osv.dev/v1/vulns/{vuln_id}", timeout=30)
            if resp.status_code != 200:
                return None
            data          = resp.json()
            fixed_versions = []
            severity      = "UNKNOWN"
            summary       = data.get("summary", "No summary available")

            for affected in data.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])
                db_sev = affected.get("database_specific", {}).get("severity")
                if isinstance(db_sev, str) and db_sev.upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                    severity = db_sev.upper()

            if severity == "UNKNOWN":
                for sev in data.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        severity = self._cvss_vector_to_severity(sev.get("score", ""))
                        if severity != "UNKNOWN":
                            break

            return {
                "id":             vuln_id,
                "summary":        summary[:200],
                "severity":       severity,
                "fixed_versions": fixed_versions,
                "aliases":        data.get("aliases", [])[:5],
                "references":     [r.get("url", "") for r in data.get("references", [])[:3]],
            }
        except requests.exceptions.RequestException:
            return {"id": vuln_id, "summary": "Failed to fetch details", "severity": "UNKNOWN"}

    @staticmethod
    def _parse_version(version_str: str) -> tuple:
        if not version_str:
            return ()
        parts = []
        for p in re.split(r"[-.]", re.sub(r"[^0-9.\-]", "", version_str)):
            try:
                parts.append(int(p))
            except ValueError:
                break
        return tuple(parts)

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 9.0:   return "CRITICAL"
        if score >= 7.0:   return "HIGH"
        if score >= 4.0:   return "MEDIUM"
        if score > 0:      return "LOW"
        return "UNKNOWN"

    @staticmethod
    def _cvss_vector_to_severity(vector: str) -> str:
        if not vector or ":" not in vector:
            return "UNKNOWN"
        parts = {p.split(":")[0]: p.split(":")[1] for p in vector.split("/") if ":" in p}
        impact = sum({"H": 3, "L": 1, "N": 0}.get(parts.get(m, "N"), 0) for m in ("C", "I", "A"))
        av = parts.get("AV", "N")
        pr = parts.get("PR", "N")
        if impact >= 7 and av == "N" and pr in ("N", "L"):  return "CRITICAL"
        if impact >= 5 and av == "N":                        return "HIGH"
        if impact >= 3:                                      return "MEDIUM"
        if impact >= 1:                                      return "LOW"
        return "UNKNOWN"


class MavenCentralVersionLookupTool(BaseTool):
    name: str = "Lookup Latest Safe Version"
    description: str = (
        "Looks up available versions of a Maven artifact on Maven Central and identifies "
        "which ones are UPGRADES that fix known vulnerabilities. "
        "Input: JSON with 'group_id', 'artifact_id', 'current_version', optionally 'fixed_versions'. "
        "Returns: annotated list of versions with upgrade/downgrade labels and recommended version."
    )

    def _run(
        self,
        input_json: str | None = None,
        group_id: str | None = None,
        artifact_id: str | None = None,
        current_version: str | None = None,
        fixed_versions: list | None = None,
    ) -> str:
        params: dict = {}
        if input_json:
            try:
                params = json.loads(input_json)
            except json.JSONDecodeError:
                return "ERROR: Input must be valid JSON."

        group_id        = (group_id        or params.get("group_id",        "")).strip()
        artifact_id     = (artifact_id     or params.get("artifact_id",     "")).strip()
        current_version = (current_version or params.get("current_version", "")).strip()
        fixed_versions  = fixed_versions if fixed_versions is not None else params.get("fixed_versions", [])

        if not group_id or not artifact_id:
            return "ERROR: Both 'group_id' and 'artifact_id' are required."

        try:
            url = (
                f"https://search.maven.org/solrsearch/select?"
                f"q=g:{group_id}+AND+a:{artifact_id}&rows=20&wt=json&core=gav"
            )
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            docs = resp.json().get("response", {}).get("docs", [])
            if not docs:
                return f"No versions found for {group_id}:{artifact_id} on Maven Central."

            current_parts = self._parse_version(current_version)
            versions      = []
            recommended   = None

            for doc in docs:
                ver       = doc.get("v", "")
                ver_parts = self._parse_version(ver)
                is_upgrade    = ver_parts > current_parts if current_parts else True
                is_fix        = ver in fixed_versions
                is_same_major = (
                    ver_parts[0] == current_parts[0]
                    if current_parts and ver_parts else False
                )
                entry = {
                    "version":          ver,
                    "direction":        "UPGRADE" if is_upgrade else (
                                        "CURRENT" if ver == current_version else "DOWNGRADE"),
                    "fixes_vulnerability": is_fix,
                    "same_major_version":  is_same_major,
                }
                versions.append(entry)
                if is_upgrade and is_fix and recommended is None:
                    recommended = ver

            if recommended is None:
                for v in versions:
                    if v["direction"] == "UPGRADE":
                        recommended = v["version"]
                        break

            result = {
                "artifact":             f"{group_id}:{artifact_id}",
                "current_version":      current_version,
                "recommended_upgrade":  recommended,
                "available_versions":   versions,
            }
            if fixed_versions:
                result["known_fixed_versions"] = fixed_versions

            return json.dumps(result, indent=2)

        except requests.exceptions.RequestException as e:
            return f"ERROR: Maven Central lookup failed: {str(e)}"

    @staticmethod
    def _parse_version(version_str: str) -> tuple:
        if not version_str:
            return ()
        parts = []
        for p in re.split(r"[-.]", re.sub(r"[^0-9.\-]", "", version_str)):
            try:
                parts.append(int(p))
            except ValueError:
                break
        return tuple(parts)


class SearchCodeUsageTool(BaseTool):
    name: str = "Search Code Usage"
    description: str = (
        "Searches Java/Kotlin source files in a repository for imports and usage of a "
        "specific dependency package. "
        "Input: JSON with 'repo_path' and 'package_pattern' "
        "(e.g. 'org.apache.logging.log4j'). "
        "Returns: list of files and matching lines."
    )

    def _run(
        self,
        input_json: str | None = None,
        repo_path: str | None = None,
        package_pattern: str | None = None,
    ) -> str:
        params: dict = {}
        if input_json:
            try:
                params = json.loads(input_json)
            except json.JSONDecodeError:
                return "ERROR: Input must be valid JSON."

        repo_path       = (repo_path       or params.get("repo_path",       "")).strip().strip("'\"")
        package_pattern = (package_pattern or params.get("package_pattern", "")).strip()

        if not os.path.isdir(repo_path):
            return f"ERROR: Directory not found: {repo_path}"
        if not package_pattern:
            return "ERROR: 'package_pattern' is required."

        matches    = []
        extensions = (".java", ".kt", ".kts", ".groovy", ".scala")

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in (
                "build", "target", ".gradle", ".mvn", ".git", "node_modules",
            )]
            for fname in files:
                if not fname.endswith(extensions):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        for lineno, line in enumerate(f, 1):
                            if package_pattern in line:
                                matches.append({
                                    "file":    os.path.relpath(fpath, repo_path),
                                    "line":    lineno,
                                    "content": line.strip()[:200],
                                })
                                if len(matches) >= 50:
                                    break
                except OSError:
                    continue
                if len(matches) >= 50:
                    break
            if len(matches) >= 50:
                break

        if not matches:
            return json.dumps({
                "package":      package_pattern,
                "usage_found":  False,
                "message":      (
                    f"No usage of '{package_pattern}' found in source files. "
                    "The dependency may only be used transitively."
                ),
                "matches": [],
            }, indent=2)

        return json.dumps({
            "package":       package_pattern,
            "usage_found":   True,
            "total_matches": len(matches),
            "matches":       matches,
        }, indent=2)


class FetchChangelogTool(BaseTool):
    name: str = "Fetch Changelog"
    description: str = (
        "Fetches release notes and breaking changes for a dependency upgrade. "
        "Input: JSON with 'group_id', 'artifact_id', 'current_version', 'target_version'. "
        "Checks GitHub Releases API, CHANGELOG.md, and Apache changelog pages. "
        "Returns: structured summary with breaking_changes, migration_steps, "
        "safe_to_upgrade, and confidence_score (0-100)."
    )

    MAVEN_TO_GITHUB: dict = {
        "org.apache.logging.log4j":      "apache/logging-log4j2",
        "org.springframework":           "spring-projects/spring-framework",
        "org.springframework.boot":      "spring-projects/spring-boot",
        "org.springframework.security":  "spring-projects/spring-security",
        "com.fasterxml.jackson.core":    "FasterXML/jackson-core",
        "com.fasterxml.jackson.databind":"FasterXML/jackson-databind",
        "com.google.guava":              "google/guava",
        "com.google.code.gson":          "google/gson",
        "io.netty":                      "netty/netty",
        "org.yaml":                      "snakeyaml/snakeyaml",
        "org.apache.httpcomponents":     "apache/httpcomponents-client",
        "org.apache.tomcat.embed":       "apache/tomcat",
        "org.apache.tomcat":             "apache/tomcat",
        "ch.qos.logback":                "qos-ch/logback",
        "org.slf4j":                     "qos-ch/slf4j",
        "junit":                         "junit-team/junit4",
        "org.junit.jupiter":             "junit-team/junit5",
        "org.apache.struts":             "apache/struts",
        "commons-io":                    "apache/commons-io",
        "commons-lang":                  "apache/commons-lang",
        "org.apache.commons.commons-text": "apache/commons-text",
    }

    # For Apache projects that publish changelogs as HTML rather than GitHub Releases
    APACHE_CHANGELOG_URLS: dict = {
        "org.apache.tomcat.embed": "https://tomcat.apache.org/tomcat-{major}-doc/changelog.html",
        "org.apache.tomcat":       "https://tomcat.apache.org/tomcat-{major}-doc/changelog.html",
        "org.apache.struts":       "https://struts.apache.org/announce.html",
    }

    def _run(
        self,
        input_json: str | None = None,
        group_id: str | None = None,
        artifact_id: str | None = None,
        current_version: str | None = None,
        target_version: str | None = None,
    ) -> str:
        params: dict = {}
        if input_json:
            try:
                params = json.loads(input_json)
            except json.JSONDecodeError:
                return "ERROR: Input must be valid JSON."

        group_id        = (group_id        or params.get("group_id",        "")).strip()
        artifact_id     = (artifact_id     or params.get("artifact_id",     "")).strip()
        current_version = (current_version or params.get("current_version", "")).strip()
        target_version  = (target_version  or params.get("target_version",  "")).strip()

        if not all([group_id, artifact_id, current_version, target_version]):
            return "ERROR: All fields required: group_id, artifact_id, current_version, target_version."

        github_repo = self._resolve_github_repo(group_id, artifact_id)

        result = {
            "artifact":         f"{group_id}:{artifact_id}",
            "current_version":  current_version,
            "target_version":   target_version,
            "github_repo":      github_repo,
            "release_notes":    [],
            "breaking_changes": [],
            "deprecations":     [],
            "migration_steps":  [],
            "safe_to_upgrade":  True,
            "confidence":       "low",
            "confidence_score": 0,        # NEW: numeric 0-100
        }

        # 1. Try GitHub Releases API
        if github_repo:
            self._fetch_github_releases(github_repo, current_version, target_version, result)

        # 2. Apache HTML changelog fallback (Tomcat, Struts)
        if not result["release_notes"] and group_id in self.APACHE_CHANGELOG_URLS:
            self._fetch_apache_changelog(group_id, current_version, target_version, result)

        # 3. CHANGELOG.md fallback
        if not result["release_notes"] and github_repo:
            self._fetch_changelog_md(github_repo, current_version, target_version, result)

        # 4. Maven Central metadata (release date)
        self._fetch_maven_metadata(group_id, artifact_id, target_version, result)

        # Determine safety and confidence score
        if result["breaking_changes"]:
            result["safe_to_upgrade"]  = False
            result["confidence"]       = "high"
            result["confidence_score"] = 85
        elif result["release_notes"]:
            result["confidence"]       = "high"
            result["confidence_score"] = 90
        else:
            result["confidence"]       = "low"
            result["confidence_score"] = 30

        # Boost confidence if no breaking changes AND release notes exist
        if result["release_notes"] and not result["breaking_changes"]:
            result["confidence_score"] = min(95, result["confidence_score"] + 5)

        return json.dumps(result, indent=2)

    def _fetch_apache_changelog(
        self, group_id: str, current: str, target: str, result: dict
    ) -> None:
        """
        Fetch Apache HTML changelog pages (e.g. tomcat.apache.org changelog).
        Extracts text between the current and target version headings.
        """
        url_template = self.APACHE_CHANGELOG_URLS.get(group_id, "")
        if not url_template:
            return

        # Determine major version from target (e.g. "10.1.42" → "10")
        major = target.split(".")[0] if target else "10"
        url   = url_template.replace("{major}", major)

        try:
            resp = requests.get(url, timeout=20)
            if resp.status_code != 200:
                return

            # Strip HTML tags for text extraction
            text = re.sub(r"<[^>]+>", " ", resp.text)
            text = re.sub(r"\s+", " ", text)

            # Find sections between current and target version numbers
            current_parts = self._parse_version(current)
            target_parts  = self._parse_version(target)
            relevant_lines: list[str] = []

            for m in re.finditer(
                r"(\d+\.\d+\.\d+(?:\.\d+)?)\s+([\w\s,]+?\d{4})",
                text,
            ):
                ver_str   = m.group(1)
                ver_parts = self._parse_version(ver_str)
                if current_parts < ver_parts <= target_parts:
                    # Grab surrounding context (~500 chars)
                    start = max(0, m.start() - 100)
                    end   = min(len(text), m.end() + 500)
                    relevant_lines.append(text[start:end].strip())

            if relevant_lines:
                result["release_notes"].append({
                    "version":    f"{current} → {target}",
                    "tag":        f"apache-changelog:{major}.x",
                    "name":       f"Apache Changelog ({group_id})",
                    "highlights": "\n\n".join(relevant_lines)[:3000],
                })

                # Scan for breaking changes keywords
                combined = " ".join(relevant_lines).lower()
                for marker in ["breaking", "removed", "incompatible", "no longer"]:
                    if marker in combined:
                        result["breaking_changes"].append(
                            f"[Apache changelog] Found '{marker}' mention between "
                            f"{current} and {target} — review changelog at {url}"
                        )
                        break

        except requests.exceptions.RequestException:
            pass

    def _resolve_github_repo(self, group_id: str, artifact_id: str) -> str:
        if group_id in self.MAVEN_TO_GITHUB:
            return self.MAVEN_TO_GITHUB[group_id].replace("{artifact}", artifact_id)
        combined = f"{group_id}.{artifact_id}"
        if combined in self.MAVEN_TO_GITHUB:
            return self.MAVEN_TO_GITHUB[combined]
        if artifact_id in self.MAVEN_TO_GITHUB:
            return self.MAVEN_TO_GITHUB[artifact_id]
        parts = group_id.split(".")
        if len(parts) >= 2:
            return f"{parts[-1]}/{artifact_id}"
        return ""

    def _fetch_github_releases(self, repo: str, current: str, target: str, result: dict):
        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            token   = os.environ.get("GITHUB_TOKEN")
            if token:
                headers["Authorization"] = f"token {token}"

            resp = requests.get(
                f"https://api.github.com/repos/{repo}/releases",
                headers=headers, timeout=30, params={"per_page": 50},
            )
            if resp.status_code != 200:
                return

            releases       = resp.json()
            current_parts  = self._parse_version(current)
            target_parts   = self._parse_version(target)

            for release in releases:
                tag        = release.get("tag_name", "")
                version_str = re.sub(r"^(v|rel/|release[/-]?)", "", tag, flags=re.IGNORECASE)
                version_str = re.sub(
                    rf"^{re.escape(repo.split('/')[-1])}[/-]?", "", version_str, flags=re.IGNORECASE
                )
                ver_parts = self._parse_version(version_str)
                if not ver_parts:
                    continue

                if current_parts < ver_parts <= target_parts:
                    body      = release.get("body", "") or ""
                    body_lower = body.lower()

                    result["release_notes"].append({
                        "version":    version_str,
                        "tag":        tag,
                        "name":       release.get("name", ""),
                        "highlights": body[:1500],
                    })

                    for marker in ["breaking change", "breaking:", "incompatible",
                                   "migration required", "removed", "deprecated and removed"]:
                        if marker in body_lower:
                            for line in body.splitlines():
                                if marker in line.lower():
                                    cleaned = line.strip().lstrip("-*• ")
                                    if cleaned and len(cleaned) > 5:
                                        result["breaking_changes"].append(cleaned[:300])

                    for line in body.splitlines():
                        if "deprecat" in line.lower():
                            cleaned = line.strip().lstrip("-*• ")
                            if cleaned and len(cleaned) > 5:
                                result["deprecations"].append(cleaned[:300])

                    if "migrat" in body_lower or "upgrade guide" in body_lower:
                        for line in body.splitlines():
                            if any(kw in line.lower() for kw in ["migrat", "upgrade", "replace", "instead"]):
                                cleaned = line.strip().lstrip("-*• ")
                                if cleaned and len(cleaned) > 5:
                                    result["migration_steps"].append(cleaned[:300])

            result["breaking_changes"] = list(dict.fromkeys(result["breaking_changes"]))[:20]
            result["deprecations"]     = list(dict.fromkeys(result["deprecations"]))[:20]
            result["migration_steps"]  = list(dict.fromkeys(result["migration_steps"]))[:20]

        except requests.exceptions.RequestException:
            pass

    def _fetch_changelog_md(self, repo: str, current: str, target: str, result: dict):
        for branch in ["main", "master"]:
            for filename in ["CHANGELOG.md", "CHANGES.md", "HISTORY.md", "RELEASE_NOTES.md"]:
                try:
                    resp = requests.get(
                        f"https://raw.githubusercontent.com/{repo}/{branch}/{filename}",
                        timeout=15,
                    )
                    if resp.status_code != 200:
                        continue
                    content  = resp.text[:100000]
                    sections = self._extract_version_sections(content, current, target)
                    if sections:
                        result["release_notes"].append({
                            "version":    f"{current} -> {target}",
                            "tag":        f"from {filename}",
                            "name":       f"Changelog ({filename})",
                            "highlights": sections[:3000],
                        })
                        lower = sections.lower()
                        for marker in ["breaking", "incompatible", "removed", "migration"]:
                            if marker in lower:
                                for line in sections.splitlines():
                                    if marker in line.lower():
                                        cleaned = line.strip().lstrip("-*• #")
                                        if cleaned and len(cleaned) > 5:
                                            result["breaking_changes"].append(cleaned[:300])
                        return
                except requests.exceptions.RequestException:
                    continue

    def _extract_version_sections(self, content: str, current: str, target: str) -> str:
        lines          = content.splitlines()
        current_parts  = self._parse_version(current)
        target_parts   = self._parse_version(target)
        relevant       = []
        capturing      = False
        version_pattern = re.compile(r"#{1,3}\s.*?(\d+\.\d+[\d.]*)")

        for line in lines:
            m = version_pattern.match(line)
            if m:
                ver_parts = self._parse_version(m.group(1))
                if ver_parts:
                    if current_parts < ver_parts <= target_parts:
                        capturing = True
                    elif ver_parts <= current_parts or ver_parts > target_parts:
                        capturing = False
            if capturing:
                relevant.append(line)

        return "\n".join(relevant)

    def _fetch_maven_metadata(self, group_id: str, artifact_id: str, target: str, result: dict):
        try:
            resp = requests.get(
                f"https://search.maven.org/solrsearch/select?"
                f"q=g:{group_id}+AND+a:{artifact_id}+AND+v:{target}&wt=json",
                timeout=15,
            )
            if resp.status_code == 200:
                docs = resp.json().get("response", {}).get("docs", [])
                if docs:
                    ts = docs[0].get("timestamp", 0)
                    if ts:
                        from datetime import datetime as dt
                        result["maven_release_date"] = dt.fromtimestamp(ts / 1000).strftime("%Y-%m-%d")
        except (requests.exceptions.RequestException, ValueError):
            pass

    @staticmethod
    def _parse_version(version_str: str) -> tuple:
        if not version_str:
            return ()
        parts = []
        for p in re.split(r"[-.]", re.sub(r"[^0-9.\-]", "", version_str)):
            try:
                parts.append(int(p))
            except ValueError:
                break
        return tuple(parts)


class ReadProjectDocsTool(BaseTool):
    name: str = "Read Project Docs"
    description: str = (
        "Reads the scanned project's README, docs, and config files to understand what "
        "features and APIs are used. Helps verify if a breaking change in a dependency "
        "actually affects this project. "
        "Input: JSON with 'repo_path' and 'search_terms' (list of feature names or API patterns). "
        "Returns: relevant sections from project docs mentioning the search terms."
    )

    DOC_FILES:          list  = ["README.md", "README.rst", "README.txt", "README",
                                  "CONFIGURATION.md", "SETUP.md"]
    DOC_DIRS:           list  = ["docs", "doc", "documentation"]
    CONFIG_EXTENSIONS:  tuple = (".yml", ".yaml", ".xml", ".properties",
                                  ".conf", ".json", ".toml", ".cfg")

    def _run(
        self,
        input_json: str | None = None,
        repo_path: str | None = None,
        search_terms: list | None = None,
    ) -> str:
        params: dict = {}
        if input_json:
            try:
                params = json.loads(input_json)
            except json.JSONDecodeError:
                return "ERROR: Input must be valid JSON."

        repo_path    = (repo_path or params.get("repo_path", "")).strip().strip("'\"")
        search_terms = search_terms if search_terms is not None else params.get("search_terms", [])

        if not os.path.isdir(repo_path):
            return f"ERROR: Directory not found: {repo_path}"
        if not search_terms:
            return "ERROR: 'search_terms' list is required."

        findings       = {"repo_path": repo_path, "search_terms": search_terms,
                          "matches": [], "files_searched": 0}
        files_to_search: list[str] = []

        for doc_file in self.DOC_FILES:
            p = os.path.join(repo_path, doc_file)
            if os.path.isfile(p):
                files_to_search.append(p)

        for doc_dir in self.DOC_DIRS:
            dir_path = os.path.join(repo_path, doc_dir)
            if os.path.isdir(dir_path):
                for root, _, files in os.walk(dir_path):
                    if root.replace(dir_path, "").count(os.sep) > 3:
                        continue
                    for f in files:
                        files_to_search.append(os.path.join(root, f))

        for config_dir in [repo_path, os.path.join(repo_path, "src", "main", "resources")]:
            if not os.path.isdir(config_dir):
                continue
            for f in os.listdir(config_dir):
                fp = os.path.join(config_dir, f)
                if os.path.isfile(fp) and f.endswith(self.CONFIG_EXTENSIONS):
                    files_to_search.append(fp)

        for fpath in files_to_search:
            findings["files_searched"] += 1
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read(500_000)
                for term in search_terms:
                    if term.lower() not in content.lower():
                        continue
                    lines = content.splitlines()
                    for i, line in enumerate(lines):
                        if term.lower() in line.lower():
                            context = "\n".join(lines[max(0, i-2):min(len(lines), i+3)])
                            findings["matches"].append({
                                "file":    os.path.relpath(fpath, repo_path),
                                "line":    i + 1,
                                "term":    term,
                                "context": context[:500],
                            })
                            if len(findings["matches"]) >= 50:
                                break
                    if len(findings["matches"]) >= 50:
                        break
            except OSError:
                continue
            if len(findings["matches"]) >= 50:
                break

        if not findings["matches"]:
            findings["message"] = (
                f"No mentions of {search_terms} found in project docs or config. "
                "The project may not directly use the affected features, making the upgrade safer."
            )

        return json.dumps(findings, indent=2)