"""
VulnHawk - Custom CrewAI Tools
Handles: build system detection, dependency extraction, OSV vulnerability lookup,
Maven Central version lookup, source code usage search.
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
# Key: "vendor:product", Value: list of NVD vulnerability dicts
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
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradlew",
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
        "Extracts all dependencies (including transitive) from a Maven or Gradle project. "
        "Input: repo_path (string) and build_system ('maven' or 'gradle'). "
        "Returns a JSON list of dependencies with groupId, artifactId, and version."
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

    def _extract_maven(self, repo_path: str) -> str:
        pom_path = os.path.join(repo_path, "pom.xml")
        if not os.path.exists(pom_path):
            return "ERROR: pom.xml not found"

        dependencies = []

        try:
            result = subprocess.run(
                ["mvn", "dependency:list", "-DoutputAbsoluteArtifactFilename=false", "-q"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith("[") or line.startswith("---"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 4:
                        dependencies.append({
                            "group_id": parts[0].strip(),
                            "artifact_id": parts[1].strip(),
                            "version": parts[3].strip(),
                            "scope": parts[4].strip() if len(parts) > 4 else "compile",
                        })
                if dependencies:
                    return json.dumps(dependencies, indent=2)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return self._parse_pom_xml(pom_path)

    def _parse_pom_xml(self, pom_path: str) -> str:
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

            for dep in root.iter(f"{ns_prefix}dependency"):
                group_id = dep.find(f"{ns_prefix}groupId")
                artifact_id = dep.find(f"{ns_prefix}artifactId")
                version = dep.find(f"{ns_prefix}version")
                scope = dep.find(f"{ns_prefix}scope")

                if group_id is not None and artifact_id is not None:
                    dep_info = {
                        "group_id": group_id.text or "",
                        "artifact_id": artifact_id.text or "",
                        "version": version.text if version is not None else "UNKNOWN",
                        "scope": scope.text if scope is not None else "compile",
                    }
                    if dep_info["version"].startswith("${"):
                        prop_name = dep_info["version"][2:-1]
                        for prop in root.iter(f"{ns_prefix}{prop_name}"):
                            dep_info["version"] = prop.text or "UNKNOWN"
                            break
                        props = root.find(f"{ns_prefix}properties")
                        if props is not None:
                            prop_elem = props.find(f"{ns_prefix}{prop_name}")
                            if prop_elem is not None:
                                dep_info["version"] = prop_elem.text or "UNKNOWN"

                    dependencies.append(dep_info)

        except ET.ParseError as e:
            return f"ERROR: Failed to parse pom.xml: {e}"

        if not dependencies:
            return "ERROR: No dependencies found in pom.xml"

        return json.dumps(dependencies, indent=2)

    def _extract_gradle(self, repo_path: str) -> str:
        gradle_cmd = None
        if os.path.exists(os.path.join(repo_path, "gradlew")):
            gradle_cmd = os.path.join(repo_path, "gradlew")
            try:
                os.chmod(gradle_cmd, 0o755)
            except PermissionError:
                # If we can't chmod (e.g., restricted repo), still try to execute if possible.
                pass
        else:
            try:
                subprocess.run(["gradle", "--version"], capture_output=True, timeout=10)
                gradle_cmd = "gradle"
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        if gradle_cmd:
            for config in ["runtimeClasspath", "compileClasspath"]:
                try:
                    result = subprocess.run(
                        [gradle_cmd, "dependencies", "--configuration", config, "--no-daemon"],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if result.returncode == 0:
                        parsed = self._parse_gradle_tree(result.stdout)
                        if not parsed.startswith("ERROR"):
                            return parsed
                except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired):
                    pass

        return self._parse_build_gradle(repo_path)

    def _parse_gradle_tree(self, output: str) -> str:
        dependencies = []
        seen = set()
        pattern = re.compile(r"[\+\\|`\- ]+(\S+):(\S+):(\S+?)(?:\s.*)?$")

        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                group_id = match.group(1)
                artifact_id = match.group(2)
                version = match.group(3)
                if " -> " in version:
                    version = version.split(" -> ")[-1]
                version = version.rstrip("(*)")

                key = f"{group_id}:{artifact_id}:{version}"
                if key not in seen:
                    seen.add(key)
                    dependencies.append({
                        "group_id": group_id,
                        "artifact_id": artifact_id,
                        "version": version,
                        "scope": "runtime",
                    })

        if not dependencies:
            return "ERROR: Could not parse gradle dependency tree"

        return json.dumps(dependencies, indent=2)

    def _parse_build_gradle(self, repo_path: str) -> str:
        import xml.etree.ElementTree as ET

        dependencies = []
        seen: set[str] = set()

        for filename in ["build.gradle", "build.gradle.kts"]:
            filepath = os.path.join(repo_path, filename)
            if not os.path.exists(filepath):
                continue

            with open(filepath, "r") as f:
                content = f.read()

            # Resolve Spring Boot BOM so we can version unversioned deps.
            bom_versions: dict[str, str] = {}
            sb_version = self._extract_spring_boot_version(content)
            if sb_version:
                bom_versions = self._fetch_spring_boot_bom(sb_version)

            # Extract every quoted group:artifact:version coordinate in the file.
            # This catches versioned deps regardless of keyword or line continuation.
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
                        "group_id": parts[0],
                        "artifact_id": parts[1],
                        "version": parts[2],
                        "scope": "compile",
                    })

            # For unversioned deps (group:artifact only), look up in BOM.
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
                            "group_id": parts[0],
                            "artifact_id": parts[1],
                            "version": version,
                            "scope": "compile",
                        })

        if not dependencies:
            return "ERROR: No dependencies found in build.gradle"

        return json.dumps(self._expand_transitive(dependencies), indent=2)

    def _expand_transitive(self, direct: list[dict]) -> list[dict]:
        """BFS over Maven Central POMs to resolve the full transitive dependency tree."""
        import xml.etree.ElementTree as ET

        SKIP_SCOPES = {"test", "provided", "system"}
        pom_cache: dict[str, dict] = {}

        def pom_url(g: str, a: str, v: str) -> str:
            return f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom"

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

            # 1. Parent chain
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

            # 2. Properties
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

            # 3. dependencyManagement (including BOM imports)
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

            # 4. Direct dependencies
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
                        deps_direct.append({"group_id": dg, "artifact_id": da,
                                            "version": dv, "scope": ds})

            result = {"props": props, "dep_mgmt": dep_mgmt, "direct": deps_direct}
            pom_cache[key] = result
            return result

        # BFS
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
            for child in pom_data.get("direct", []):
                if f"{child['group_id']}:{child['artifact_id']}" not in seen:
                    queue.append(child)

        return resolved

    def _extract_spring_boot_version(self, content: str) -> str | None:
        """Extract Spring Boot plugin version from a Gradle build file."""
        for pattern in [
            r"""id\s*['"]org\.springframework\.boot['"]\s+version\s+['"]([^'"]+)['"]""",
            r"""id\("org\.springframework\.boot"\)\s+version\s+"([^"]+)""",
        ]:
            m = re.search(pattern, content)
            if m:
                return m.group(1)
        return None

    def _fetch_spring_boot_bom(self, version: str) -> dict[str, str]:
        """Fetch the Spring Boot BOM POM and return {group:artifact: version} map."""
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

            # Collect <properties> for ${...} resolution.
            props: dict[str, str] = {}
            props_elem = root.find(f"{ns}properties")
            if props_elem is not None:
                for child in props_elem:
                    tag = child.tag.replace(ns, "")
                    props[tag] = child.text or ""

            # Build the version map from <dependencyManagement>.
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


class OSVVulnerabilityCheckTool(BaseTool):
    name: str = "Check OSV Vulnerabilities"
    description: str = (
        "Checks a list of Maven/Gradle dependencies against the OSV database. "
        "Input: JSON list of dependencies with group_id, artifact_id, version fields. "
        "Returns: JSON report of vulnerabilities found."
    )

    # OSV does NOT track these group IDs as Maven artifacts (only GIT ranges).
    # For these, we fall back to NVD CPE-based version-range lookups.
    # Format: group_id_prefix -> (nvd_vendor, nvd_product, keyword_for_nvd_api)
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
            group_id = dep.get("group_id", "")
            artifact_id = dep.get("artifact_id", "")
            version = dep.get("version", "")

            if not all([group_id, artifact_id, version]) or version == "UNKNOWN":
                continue

            package_name = f"{group_id}:{artifact_id}"
            queries.append({
                "package": {
                    "name": package_name,
                    "ecosystem": "Maven",
                },
                "version": version,
            })
            dep_map.append(dep)

        if not queries:
            return "No valid dependencies to check (all have unknown versions)."

        all_results = []
        batch_size = 1000

        for i in range(0, len(queries), batch_size):
            batch = queries[i : i + batch_size]
            try:
                response = requests.post(
                    "https://api.osv.dev/v1/querybatch",
                    json={"queries": batch},
                    timeout=60,
                )
                response.raise_for_status()
                data = response.json()
                batch_results = data.get("results", [])
                all_results.extend(batch_results)
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
            dep = dep_map[idx]
            vulns = result.get("vulns", [])

            if not vulns:
                # OSV blind-spot fallback: check NVD for packages OSV doesn't index as Maven
                nvd_vulns = self._check_nvd_fallback(dep)
                if nvd_vulns:
                    report["vulnerable_count"] += 1
                    vuln_ids = [v["id"] for v in nvd_vulns]
                    report["vulnerabilities"].append({
                        "dependency": f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}",
                        "vulnerability_ids": vuln_ids,
                        "details": nvd_vulns,
                        "source": "NVD",
                    })
                else:
                    report["safe_count"] += 1
                continue

            report["vulnerable_count"] += 1
            vuln_ids = [v.get("id", "unknown") for v in vulns]

            vuln_details = []
            for vuln_id in vuln_ids[:5]:
                detail = self._get_vuln_details(vuln_id)
                if detail:
                    vuln_details.append(detail)

            report["vulnerabilities"].append({
                "dependency": f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}",
                "vulnerability_ids": vuln_ids,
                "details": vuln_details,
            })

        return json.dumps(report, indent=2)

    # ── NVD fallback for OSV blind spots ─────────────────────────────────────

    def _check_nvd_fallback(self, dep: dict) -> list:
        """Return list of NVD vuln dicts for deps that OSV doesn't track as Maven."""
        group_id = dep.get("group_id", "")
        version = dep.get("version", "")
        if not version or version == "UNKNOWN":
            return []

        cpe_info = self.MAVEN_CPE_MAP.get(group_id)
        if not cpe_info:
            return []

        vendor, product, keyword = cpe_info
        cache_key = f"{vendor}:{product}"

        if cache_key not in _NVD_PRODUCT_CVE_CACHE:
            _NVD_PRODUCT_CVE_CACHE[cache_key] = self._fetch_nvd_cves_for_product(keyword, product)

        affected = []
        for nvd_vuln in _NVD_PRODUCT_CVE_CACHE[cache_key]:
            detail = self._nvd_vuln_detail(nvd_vuln, version, product)
            if detail:
                affected.append(detail)
        return affected

    def _fetch_nvd_cves_for_product(self, keyword: str, product: str) -> list:
        """Fetch all NVD CVEs for a product keyword (paginated, cached per product)."""
        all_vulns = []
        start = 0
        per_page = 2000

        while True:
            try:
                resp = requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={
                        "keywordSearch": keyword,
                        "resultsPerPage": per_page,
                        "startIndex": start,
                    },
                    timeout=45,
                )
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                all_vulns.extend(vulns)
                total = data.get("totalResults", 0)
                if start + per_page >= total:
                    break
                start += per_page
                time.sleep(0.7)  # NVD rate limit: 5 req/30 s without API key
            except requests.exceptions.RequestException:
                break

        return all_vulns

    def _nvd_vuln_detail(self, nvd_vuln: dict, version: str, product: str) -> Optional[dict]:
        """
        Check if `version` falls in the NVD CPE version ranges for this CVE.
        Returns a formatted detail dict if affected, else None.
        """
        cve = nvd_vuln.get("cve", {})

        # Extract description text — full for heuristic, truncated for display
        desc_full = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc_full = d.get("value", "")
                break
        desc = desc_full[:300]

        configs = cve.get("configurations", [])
        if not configs:
            # New/unprocessed CVE — no CPE config yet.
            # Fall back to parsing version ranges from the description text.
            if not self._desc_version_affected(desc_full, version, product):
                return None
            # Description heuristic matched — build detail with a note
            severity, score = self._extract_nvd_severity(cve)
            refs = [ref.get("url", "") for ref in cve.get("references", [])[:3]]
            return {
                "id": cve.get("id", "unknown"),
                "summary": (desc or "No description available") + " [⚠ NVD CPE not yet processed]",
                "severity": severity,
                "fixed_versions": [],
                "aliases": [],
                "references": refs,
                "cvss_score": score,
            }

        ver_parts = self._parse_version(version)
        fixed_versions = []
        matched = False

        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", True):
                        continue
                    criteria = match.get("criteria", "").lower()
                    if product not in criteria:
                        continue

                    # CPE criteria format: cpe:2.3:a:vendor:product:VERSION:...
                    # Extract the version field (index 5). "*" means "any version" (use range fields).
                    criteria_raw = match.get("criteria", "")
                    cpe_fields = criteria_raw.split(":")
                    cpe_version = cpe_fields[5] if len(cpe_fields) > 5 else "*"

                    if cpe_version != "*" and cpe_version != "-":
                        # Exact-version CPE (old CVEs): only match if versions are equal
                        if self._parse_version(cpe_version) != ver_parts:
                            continue
                        matched = True
                        break  # Found an exact match, no need to check ranges

                    vsi = self._parse_version(match.get("versionStartIncluding", ""))
                    vse = self._parse_version(match.get("versionStartExcluding", ""))
                    vei = self._parse_version(match.get("versionEndIncluding", ""))
                    vee = self._parse_version(match.get("versionEndExcluding", ""))

                    # If criteria is wildcard AND no range constraints → skip (too broad, avoid FP)
                    if not vsi and not vse and not vei and not vee:
                        continue

                    start_ok = (not vsi and not vse) or \
                               (vsi and ver_parts >= vsi) or \
                               (vse and ver_parts > vse)
                    end_ok = (not vei and not vee) or \
                             (vei and ver_parts <= vei) or \
                             (vee and ver_parts < vee)

                    if start_ok and end_ok:
                        matched = True
                        if vee:
                            fv = match.get("versionEndExcluding", "")
                            if fv and fv not in fixed_versions:
                                fixed_versions.append(fv)

        if not matched:
            return None

        severity, score = self._extract_nvd_severity(cve)
        refs = [ref.get("url", "") for ref in cve.get("references", [])[:3]]

        return {
            "id": cve.get("id", "unknown"),
            "summary": desc or "No description available",
            "severity": severity,
            "fixed_versions": fixed_versions,
            "aliases": [],
            "references": refs,
            "cvss_score": score,
        }

    def _extract_nvd_severity(self, cve: dict) -> tuple:
        """Extract (severity_str, score_float) from NVD CVE metrics."""
        severity = "UNKNOWN"
        score = None
        for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(metric_key, [])
            if metrics:
                cvss_data = metrics[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                sev = cvss_data.get("baseSeverity", "")
                if sev:
                    severity = sev.upper()
                elif score is not None:
                    severity = self._score_to_severity(float(score))
                break
        return severity, score

    def _desc_version_affected(self, desc: str, version: str, product: str) -> bool:
        """
        Heuristic: parse version ranges from CVE description text.
        Used only for new CVEs that NVD hasn't yet assigned CPE configurations.
        Patterns matched:
          - "from X.Y.Z through A.B.C"  (both inclusive)
          - "through A.B.C"             (any version up to A.B.C)
          - "before A.B.C"              (exclusive upper bound)
        """
        if not desc or product not in desc.lower():
            return False

        ver_parts = self._parse_version(version)
        if not ver_parts:
            return False

        # "from X.Y.Z[-pre] through A.B.C[-pre]"
        for m in re.finditer(
            r'(?:from\s+([\d]+\.[\d]+[.\d]*(?:-[\w.]+)?)\s+)?'
            r'through\s+([\d]+\.[\d]+[.\d]*(?:-[\w.]+)?)',
            desc, re.IGNORECASE,
        ):
            start_str = m.group(1) or ""
            end_str   = m.group(2) or ""
            end_parts = self._parse_version(end_str)
            if not end_parts or ver_parts > end_parts:
                continue
            if start_str:
                start_parts = self._parse_version(start_str)
                if ver_parts < start_parts:
                    continue
            return True

        # "before A.B.C" (exclusive upper bound)
        for m in re.finditer(r'before\s+([\d]+\.[\d]+[.\d]*)', desc, re.IGNORECASE):
            end_parts = self._parse_version(m.group(1))
            if end_parts and ver_parts < end_parts:
                return True

        return False

    def _get_vuln_details(self, vuln_id: str) -> Optional[dict]:
        try:
            response = requests.get(
                f"https://api.osv.dev/v1/vulns/{vuln_id}",
                timeout=30,
            )
            if response.status_code != 200:
                return None

            data = response.json()

            fixed_versions = []
            severity = "UNKNOWN"
            summary = data.get("summary", "No summary available")

            for affected in data.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])

                db_specific = affected.get("database_specific", {})
                if severity == "UNKNOWN":
                    db_sev = db_specific.get("severity")
                    if isinstance(db_sev, str) and db_sev.upper() in (
                        "LOW", "MEDIUM", "HIGH", "CRITICAL",
                    ):
                        severity = db_sev.upper()
                    elif "cvss_score" in db_specific:
                        score = db_specific["cvss_score"]
                        severity = self._score_to_severity(score)

            if severity == "UNKNOWN":
                top_db = data.get("database_specific", {})
                top_sev = top_db.get("severity")
                if isinstance(top_sev, str) and top_sev.upper() in (
                    "LOW", "MEDIUM", "HIGH", "CRITICAL",
                ):
                    severity = top_sev.upper()

            if severity == "UNKNOWN":
                for sev in data.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        score_str = sev.get("score", "")
                        severity = self._cvss_vector_to_severity(score_str)
                        if severity != "UNKNOWN":
                            break

            return {
                "id": vuln_id,
                "summary": summary[:200],
                "severity": severity,
                "fixed_versions": fixed_versions,
                "aliases": data.get("aliases", [])[:5],
                "references": [
                    ref.get("url", "")
                    for ref in data.get("references", [])[:3]
                ],
            }

        except requests.exceptions.RequestException:
            return {"id": vuln_id, "summary": "Failed to fetch details", "severity": "UNKNOWN"}

    @staticmethod
    def _parse_version(version_str: str) -> tuple:
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

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "UNKNOWN"

    @staticmethod
    def _cvss_vector_to_severity(vector: str) -> str:
        if not vector or ":" not in vector:
            return "UNKNOWN"

        parts = {p.split(":")[0]: p.split(":")[1]
                 for p in vector.split("/") if ":" in p}

        impact_vals = {"H": 3, "L": 1, "N": 0}
        impact = sum(
            impact_vals.get(parts.get(m, "N"), 0)
            for m in ("C", "I", "A")
        )

        av = parts.get("AV", "N")
        pr = parts.get("PR", "N")

        if impact >= 7 and av == "N" and pr in ("N", "L"):
            return "CRITICAL"
        if impact >= 5 and av == "N":
            return "HIGH"
        if impact >= 3:
            return "MEDIUM"
        if impact >= 1:
            return "LOW"
        return "UNKNOWN"


class MavenCentralVersionLookupTool(BaseTool):
    name: str = "Lookup Latest Safe Version"
    description: str = (
        "Looks up available versions of a Maven artifact on Maven Central and identifies "
        "which ones are UPGRADES that fix known vulnerabilities. "
        "Input: either a JSON string with 'group_id', 'artifact_id', 'current_version', and "
        "optionally 'fixed_versions', or pass those fields as direct tool arguments. "
        "Returns: annotated list of versions with upgrade/downgrade labels."
    )

    def _run(
        self,
        input_json: str | None = None,
        group_id: str | None = None,
        artifact_id: str | None = None,
        current_version: str | None = None,
        fixed_versions: list | None = None,
    ) -> str:
        params = {}
        if input_json:
            try:
                params = json.loads(input_json)
            except json.JSONDecodeError:
                return "ERROR: Input must be valid JSON with 'group_id' and 'artifact_id'."

        group_id = (group_id or params.get("group_id", "")).strip()
        artifact_id = (artifact_id or params.get("artifact_id", "")).strip()
        current_version = (current_version or params.get("current_version", "")).strip()
        fixed_versions = fixed_versions if fixed_versions is not None else params.get("fixed_versions", [])

        if not group_id or not artifact_id:
            return "ERROR: Both 'group_id' and 'artifact_id' are required."

        try:
            url = (
                f"https://search.maven.org/solrsearch/select?"
                f"q=g:{group_id}+AND+a:{artifact_id}&rows=20&wt=json&core=gav"
            )
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            docs = data.get("response", {}).get("docs", [])
            if not docs:
                return f"No versions found for {group_id}:{artifact_id} on Maven Central."

            current_parts = self._parse_version(current_version)

            versions = []
            recommended = None
            for doc in docs:
                ver = doc.get("v", "")
                ver_parts = self._parse_version(ver)
                is_upgrade = ver_parts > current_parts if current_parts else True
                is_fix = ver in fixed_versions
                is_same_major = (
                    ver_parts[0] == current_parts[0]
                    if current_parts and ver_parts else False
                )

                entry = {
                    "version": ver,
                    "direction": "UPGRADE" if is_upgrade else (
                        "CURRENT" if ver == current_version else "DOWNGRADE"
                    ),
                    "fixes_vulnerability": is_fix,
                    "same_major_version": is_same_major,
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
                "artifact": f"{group_id}:{artifact_id}",
                "current_version": current_version,
                "recommended_upgrade": recommended,
                "available_versions": versions,
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
        clean = re.split(r"[-.]", re.sub(r"[^0-9.\-]", "", version_str))
        parts = []
        for p in clean:
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
        "Input: either a JSON string with 'repo_path' and 'package_pattern' "
        "(e.g. 'org.apache.logging.log4j') or pass those as direct tool arguments. "
        "Returns: list of files and matching lines."
    )

    def _run(
        self,
        input_json: str | None = None,
        repo_path: str | None = None,
        package_pattern: str | None = None,
    ) -> str:
        params = {}
        if input_json:
            try:
                params = json.loads(input_json)
            except json.JSONDecodeError:
                return "ERROR: Input must be valid JSON with 'repo_path' and 'package_pattern'."

        repo_path = (repo_path or params.get("repo_path", "")).strip().strip("'\"")
        package_pattern = (package_pattern or params.get("package_pattern", "")).strip()

        if not os.path.isdir(repo_path):
            return f"ERROR: Directory not found: {repo_path}"
        if not package_pattern:
            return "ERROR: 'package_pattern' is required."

        matches = []
        extensions = (".java", ".kt", ".kts", ".groovy", ".scala")
        max_matches = 50

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
                                rel = os.path.relpath(fpath, repo_path)
                                matches.append({
                                    "file": rel,
                                    "line": lineno,
                                    "content": line.strip()[:200],
                                })
                                if len(matches) >= max_matches:
                                    break
                except OSError:
                    continue
                if len(matches) >= max_matches:
                    break
            if len(matches) >= max_matches:
                break

        if not matches:
            return json.dumps({
                "package": package_pattern,
                "usage_found": False,
                "message": f"No usage of '{package_pattern}' found in source files. "
                           "The dependency may only be used transitively.",
                "matches": [],
            }, indent=2)

        return json.dumps({
            "package": package_pattern,
            "usage_found": True,
            "total_matches": len(matches),
            "matches": matches,
        }, indent=2)


class FetchChangelogTool(BaseTool):
    name: str = "Fetch Changelog"
    description: str = (
        "Fetches release notes, breaking changes, and migration guides for a dependency upgrade. "
        "Input: either a JSON string with 'group_id', 'artifact_id', 'current_version', "
        "'target_version', or pass those as direct tool arguments. "
        "Checks GitHub Releases API, CHANGELOG.md, and Maven Central metadata. "
        "Returns: structured summary with breaking_changes, migration_steps, safe_to_upgrade."
    )

    # Maps common Maven group IDs to GitHub owner/repo
    MAVEN_TO_GITHUB: dict = {
        "org.apache.logging.log4j": "apache/logging-log4j2",
        "org.apache.commons": "apache/commons-{artifact}",
        "org.springframework": "spring-projects/spring-framework",
        "org.springframework.boot": "spring-projects/spring-boot",
        "org.springframework.security": "spring-projects/spring-security",
        "com.fasterxml.jackson.core": "FasterXML/jackson-core",
        "com.fasterxml.jackson.databind": "FasterXML/jackson-databind",
        "com.google.guava": "google/guava",
        "com.google.code.gson": "google/gson",
        "io.netty": "netty/netty",
        "org.yaml": "snakeyaml/snakeyaml",
        "org.apache.httpcomponents": "apache/httpcomponents-client",
        "org.apache.tomcat.embed": "apache/tomcat",
        "ch.qos.logback": "qos-ch/logback",
        "org.slf4j": "qos-ch/slf4j",
        "junit": "junit-team/junit4",
        "org.junit.jupiter": "junit-team/junit5",
        "org.apache.struts": "apache/struts",
        "commons-io": "apache/commons-io",
        "commons-lang": "apache/commons-lang",
        "org.apache.commons.commons-text": "apache/commons-text",
    }

    def _run(
        self,
        input_json: str | None = None,
        group_id: str | None = None,
        artifact_id: str | None = None,
        current_version: str | None = None,
        target_version: str | None = None,
    ) -> str:
        params = {}
        if input_json:
            try:
                params = json.loads(input_json)
            except json.JSONDecodeError:
                return "ERROR: Input must be valid JSON with 'group_id', 'artifact_id', 'current_version', 'target_version'."

        group_id = (group_id or params.get("group_id", "")).strip()
        artifact_id = (artifact_id or params.get("artifact_id", "")).strip()
        current_version = (current_version or params.get("current_version", "")).strip()
        target_version = (target_version or params.get("target_version", "")).strip()

        if not all([group_id, artifact_id, current_version, target_version]):
            return "ERROR: All fields required: group_id, artifact_id, current_version, target_version."

        github_repo = self._resolve_github_repo(group_id, artifact_id)

        result = {
            "artifact": f"{group_id}:{artifact_id}",
            "current_version": current_version,
            "target_version": target_version,
            "github_repo": github_repo,
            "release_notes": [],
            "breaking_changes": [],
            "deprecations": [],
            "migration_steps": [],
            "safe_to_upgrade": True,
            "confidence": "low",
        }

        if github_repo:
            self._fetch_github_releases(github_repo, current_version, target_version, result)
            if not result["release_notes"]:
                self._fetch_changelog_md(github_repo, current_version, target_version, result)

        self._fetch_maven_metadata(group_id, artifact_id, target_version, result)

        # Determine safety based on findings
        if result["breaking_changes"]:
            result["safe_to_upgrade"] = False
            result["confidence"] = "high"
        elif result["release_notes"]:
            result["confidence"] = "high" if len(result["release_notes"]) > 0 else "medium"
        else:
            result["confidence"] = "low"

        return json.dumps(result, indent=2)

    def _resolve_github_repo(self, group_id: str, artifact_id: str) -> str:
        # Direct match on group_id
        if group_id in self.MAVEN_TO_GITHUB:
            repo = self.MAVEN_TO_GITHUB[group_id]
            return repo.replace("{artifact}", artifact_id)

        # Try group_id.artifact_id combined key
        combined = f"{group_id}.{artifact_id}"
        if combined in self.MAVEN_TO_GITHUB:
            return self.MAVEN_TO_GITHUB[combined]

        # Try artifact_id alone for commons-* style
        if artifact_id in self.MAVEN_TO_GITHUB:
            return self.MAVEN_TO_GITHUB[artifact_id]

        # Heuristic: try GitHub search-style guess
        # e.g. org.apache.commons:commons-text -> apache/commons-text
        parts = group_id.split(".")
        if len(parts) >= 2:
            org = parts[-1]  # e.g. "apache" from "org.apache.commons"
            return f"{org}/{artifact_id}"

        return ""

    def _fetch_github_releases(self, repo: str, current: str, target: str, result: dict):
        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            token = os.environ.get("GITHUB_TOKEN")
            if token:
                headers["Authorization"] = f"token {token}"

            url = f"https://api.github.com/repos/{repo}/releases"
            resp = requests.get(url, headers=headers, timeout=30, params={"per_page": 50})
            if resp.status_code != 200:
                return

            releases = resp.json()
            if not isinstance(releases, list):
                return

            current_parts = self._parse_version(current)
            target_parts = self._parse_version(target)

            for release in releases:
                tag = release.get("tag_name", "")
                # Strip common prefixes like "v", "rel/", artifact name
                version_str = re.sub(r"^(v|rel/|release[/-]?)", "", tag, flags=re.IGNORECASE)
                version_str = re.sub(rf"^{re.escape(repo.split('/')[-1])}[/-]?", "", version_str, flags=re.IGNORECASE)
                ver_parts = self._parse_version(version_str)

                if not ver_parts:
                    continue

                # Include releases between current (exclusive) and target (inclusive)
                if current_parts < ver_parts <= target_parts:
                    body = release.get("body", "") or ""
                    note = {
                        "version": version_str,
                        "tag": tag,
                        "name": release.get("name", ""),
                        "highlights": body[:1500],
                    }
                    result["release_notes"].append(note)

                    # Extract breaking changes
                    body_lower = body.lower()
                    for marker in ["breaking change", "breaking:", "incompatible", "migration required",
                                   "removed", "deprecated and removed"]:
                        if marker in body_lower:
                            # Extract the relevant section
                            for line in body.splitlines():
                                if marker in line.lower() or (
                                    line.strip().startswith(("-", "*", "•")) and
                                    any(m in body_lower[max(0, body_lower.index(marker)-200):] for m in [marker])
                                ):
                                    cleaned = line.strip().lstrip("-*• ")
                                    if cleaned and len(cleaned) > 5:
                                        result["breaking_changes"].append(cleaned[:300])

                    # Extract deprecations
                    for line in body.splitlines():
                        if "deprecat" in line.lower():
                            cleaned = line.strip().lstrip("-*• ")
                            if cleaned and len(cleaned) > 5:
                                result["deprecations"].append(cleaned[:300])

                    # Extract migration steps
                    if "migrat" in body_lower or "upgrade guide" in body_lower:
                        for line in body.splitlines():
                            if any(kw in line.lower() for kw in ["migrat", "upgrade", "replace", "instead"]):
                                cleaned = line.strip().lstrip("-*• ")
                                if cleaned and len(cleaned) > 5:
                                    result["migration_steps"].append(cleaned[:300])

            # Deduplicate
            result["breaking_changes"] = list(dict.fromkeys(result["breaking_changes"]))[:20]
            result["deprecations"] = list(dict.fromkeys(result["deprecations"]))[:20]
            result["migration_steps"] = list(dict.fromkeys(result["migration_steps"]))[:20]

        except requests.exceptions.RequestException:
            pass

    def _fetch_changelog_md(self, repo: str, current: str, target: str, result: dict):
        for branch in ["main", "master"]:
            for filename in ["CHANGELOG.md", "CHANGES.md", "HISTORY.md", "RELEASE_NOTES.md"]:
                try:
                    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{filename}"
                    resp = requests.get(url, timeout=15)
                    if resp.status_code != 200:
                        continue

                    content = resp.text
                    if len(content) > 100000:
                        content = content[:100000]

                    # Extract section between current and target version
                    relevant_sections = self._extract_version_sections(content, current, target)
                    if relevant_sections:
                        result["release_notes"].append({
                            "version": f"{current} -> {target}",
                            "tag": f"from {filename}",
                            "name": f"Changelog ({filename})",
                            "highlights": relevant_sections[:3000],
                        })

                        # Scan for breaking changes in changelog
                        lower = relevant_sections.lower()
                        for marker in ["breaking", "incompatible", "removed", "migration"]:
                            if marker in lower:
                                for line in relevant_sections.splitlines():
                                    if marker in line.lower():
                                        cleaned = line.strip().lstrip("-*• #")
                                        if cleaned and len(cleaned) > 5:
                                            result["breaking_changes"].append(cleaned[:300])
                        return  # Found changelog, stop searching
                except requests.exceptions.RequestException:
                    continue

    def _extract_version_sections(self, content: str, current: str, target: str) -> str:
        lines = content.splitlines()
        current_parts = self._parse_version(current)
        target_parts = self._parse_version(target)
        relevant = []
        capturing = False
        version_pattern = re.compile(r"#{1,3}\s.*?(\d+\.\d+[\d.]*)")

        for line in lines:
            match = version_pattern.match(line)
            if match:
                ver_str = match.group(1)
                ver_parts = self._parse_version(ver_str)
                if ver_parts:
                    if current_parts < ver_parts <= target_parts:
                        capturing = True
                        relevant.append(line)
                        continue
                    elif ver_parts <= current_parts:
                        capturing = False
                        continue
                    elif ver_parts > target_parts:
                        capturing = False
                        continue

            if capturing:
                relevant.append(line)

        return "\n".join(relevant)

    def _fetch_maven_metadata(self, group_id: str, artifact_id: str, target_version: str, result: dict):
        try:
            url = (
                f"https://search.maven.org/solrsearch/select?"
                f"q=g:{group_id}+AND+a:{artifact_id}+AND+v:{target_version}&wt=json"
            )
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                docs = data.get("response", {}).get("docs", [])
                if docs:
                    timestamp = docs[0].get("timestamp", 0)
                    if timestamp:
                        from datetime import datetime as dt
                        release_date = dt.fromtimestamp(timestamp / 1000).strftime("%Y-%m-%d")
                        result["maven_release_date"] = release_date
        except (requests.exceptions.RequestException, ValueError):
            pass

    @staticmethod
    def _parse_version(version_str: str) -> tuple:
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


class ReadProjectDocsTool(BaseTool):
    name: str = "Read Project Docs"
    description: str = (
        "Reads the scanned project's README, docs, and config files to understand what "
        "features and APIs are used. Helps verify if a breaking change in a dependency "
        "actually affects this project. "
        "Input: either a JSON string with 'repo_path' and 'search_terms' (list of feature "
        "names or API patterns), or pass those as direct tool arguments. "
        "Returns: relevant sections from project docs mentioning the search terms."
    )

    # File patterns to search
    DOC_FILES: list = [
        "README.md", "README.rst", "README.txt", "README",
        "CONFIGURATION.md", "SETUP.md",
    ]
    DOC_DIRS: list = ["docs", "doc", "documentation"]
    CONFIG_EXTENSIONS: tuple = (".yml", ".yaml", ".xml", ".properties", ".conf", ".json", ".toml", ".cfg")

    def _run(
        self,
        input_json: str | None = None,
        repo_path: str | None = None,
        search_terms: list | None = None,
    ) -> str:
        params = {}
        if input_json:
            try:
                params = json.loads(input_json)
            except json.JSONDecodeError:
                return "ERROR: Input must be valid JSON with 'repo_path' and 'search_terms'."

        repo_path = (repo_path or params.get("repo_path", "")).strip().strip("'\"")
        search_terms = search_terms if search_terms is not None else params.get("search_terms", [])

        if not os.path.isdir(repo_path):
            return f"ERROR: Directory not found: {repo_path}"
        if not search_terms:
            return "ERROR: 'search_terms' list is required (feature names or API patterns to search for)."

        findings = {
            "repo_path": repo_path,
            "search_terms": search_terms,
            "matches": [],
            "files_searched": 0,
        }

        files_to_search = []

        # Collect doc files from root
        for doc_file in self.DOC_FILES:
            path = os.path.join(repo_path, doc_file)
            if os.path.isfile(path):
                files_to_search.append(path)

        # Collect files from doc directories
        for doc_dir in self.DOC_DIRS:
            dir_path = os.path.join(repo_path, doc_dir)
            if os.path.isdir(dir_path):
                for root, _, files in os.walk(dir_path):
                    depth = root.replace(dir_path, "").count(os.sep)
                    if depth > 3:
                        continue
                    for f in files:
                        files_to_search.append(os.path.join(root, f))

        # Collect config files from root and src/main/resources
        config_dirs = [repo_path, os.path.join(repo_path, "src", "main", "resources")]
        for config_dir in config_dirs:
            if not os.path.isdir(config_dir):
                continue
            for f in os.listdir(config_dir):
                fpath = os.path.join(config_dir, f)
                if os.path.isfile(fpath) and f.endswith(self.CONFIG_EXTENSIONS):
                    files_to_search.append(fpath)

        # Search each file for the terms
        max_matches = 50
        for fpath in files_to_search:
            findings["files_searched"] += 1
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
                    if len(content) > 500000:
                        content = content[:500000]

                for term in search_terms:
                    term_lower = term.lower()
                    content_lower = content.lower()
                    if term_lower not in content_lower:
                        continue

                    # Find matching lines with context
                    lines = content.splitlines()
                    for i, line in enumerate(lines):
                        if term_lower in line.lower():
                            start = max(0, i - 2)
                            end = min(len(lines), i + 3)
                            context = "\n".join(lines[start:end])
                            rel_path = os.path.relpath(fpath, repo_path)
                            findings["matches"].append({
                                "file": rel_path,
                                "line": i + 1,
                                "term": term,
                                "context": context[:500],
                            })
                            if len(findings["matches"]) >= max_matches:
                                break
                    if len(findings["matches"]) >= max_matches:
                        break
            except OSError:
                continue
            if len(findings["matches"]) >= max_matches:
                break

        if not findings["matches"]:
            findings["message"] = (
                f"No mentions of {search_terms} found in project documentation or config files. "
                "The project may not directly use the affected features, making the upgrade safer."
            )

        return json.dumps(findings, indent=2)
