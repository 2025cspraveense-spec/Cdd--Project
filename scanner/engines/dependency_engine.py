"""
Dependency Vulnerability Scanner
Analyzes requirements.txt, package.json, pom.xml, go.mod, Gemfile, and build.gradle.
Integrates pip-audit, OSV-Scanner, and the OSV.dev vulnerability database.
"""

import json
import logging
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional

from scanner.engines.base import BaseEngine
from scanner.models import Finding, Severity, Category

logger = logging.getLogger("scanner.engines.dependency")


class DependencyEngine(BaseEngine):
    """Detects vulnerable dependencies and known CVEs across package managers."""

    engine_name: str = "dependency_engine"

    OFFLINE_CVE_DATABASE: List[Dict[str, Any]] = [
        {
            "package": "requests",
            "ecosystem": "PyPI",
            "vulnerable_below": "2.31.0",
            "cve": "CVE-2023-32681",
            "severity": Severity.HIGH,
            "title": "Requests: Sensitive Header Leak on Cross-Domain Redirect",
            "description": "Requests forwards Proxy-Authorization headers to destination servers on cross-origin redirects.",
            "remediation": "Upgrade requests to >= 2.31.0.",
        },
        {
            "package": "urllib3",
            "ecosystem": "PyPI",
            "vulnerable_below": "2.0.7",
            "cve": "CVE-2023-45803",
            "severity": Severity.HIGH,
            "title": "urllib3: Request Body Leak on Cross-Origin Redirects",
            "description": "urllib3 strips the Authorization header on redirect, but fails to strip request body data, leaking confidential payloads.",
            "remediation": "Upgrade urllib3 to >= 2.0.7.",
        },
        {
            "package": "flask",
            "ecosystem": "PyPI",
            "vulnerable_below": "2.2.5",
            "cve": "CVE-2023-30861",
            "severity": Severity.HIGH,
            "title": "Flask: Cookie and Session Exposure in Caching Proxies",
            "description": "Flask does not add Vary: Cookie when the session is accessed, permitting proxy caches to serve session cookies to other users.",
            "remediation": "Upgrade Flask to >= 2.2.5 or >= 3.0.0.",
        },
        {
            "package": "cryptography",
            "ecosystem": "PyPI",
            "vulnerable_below": "41.0.6",
            "cve": "CVE-2023-49083",
            "severity": Severity.CRITICAL,
            "title": "Cryptography: NULL Pointer Dereference in PKCS7 Loading",
            "description": "Passing empty certificates into PKCS7 loaders causes a crash and denial of service or potential exploitation.",
            "remediation": "Upgrade cryptography to >= 41.0.6.",
        },
        {
            "package": "lodash",
            "ecosystem": "npm",
            "vulnerable_below": "4.17.21",
            "cve": "CVE-2021-23337",
            "severity": Severity.CRITICAL,
            "title": "lodash: Command Injection / Prototype Pollution in template()",
            "description": "Unsanitized input to lodash.template leads to arbitrary JavaScript execution and command injection.",
            "remediation": "Upgrade lodash to >= 4.17.21.",
        },
        {
            "package": "axios",
            "ecosystem": "npm",
            "vulnerable_below": "1.6.0",
            "cve": "CVE-2023-45857",
            "severity": Severity.HIGH,
            "title": "Axios: SSRF & Confidential Header Disclosure",
            "description": "Axios retains Authorization and Cookie headers when following absolute redirect URLs to untrusted domains.",
            "remediation": "Upgrade axios to >= 1.6.0.",
        },
        {
            "package": "log4j-core",
            "ecosystem": "Maven",
            "vulnerable_below": "2.17.1",
            "cve": "CVE-2021-44228",
            "severity": Severity.CRITICAL,
            "title": "Log4j: Remote Code Execution via JNDI Lookup (Log4Shell)",
            "description": "JNDI lookups executed in logging strings allow remote code execution from LDAP/RMI servers.",
            "remediation": "Upgrade log4j-core to >= 2.17.1.",
        },
        {
            "package": "spring-core",
            "ecosystem": "Maven",
            "vulnerable_below": "5.3.18",
            "cve": "CVE-2022-22965",
            "severity": Severity.CRITICAL,
            "title": "Spring Framework: Remote Code Execution (Spring4Shell)",
            "description": "Data binding on JDK 9+ allows overriding class loader properties and executing arbitrary payloads on Tomcat.",
            "remediation": "Upgrade spring-framework to >= 5.3.18.",
        },
    ]

    def is_pip_audit_available(self) -> bool:
        return shutil.which("pip-audit") is not None

    def is_osv_scanner_available(self) -> bool:
        return shutil.which("osv-scanner") is not None

    def scan(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        if self.is_pip_audit_available():
            findings.extend(self._run_pip_audit(source_path, scan_id))

        if self.is_osv_scanner_available():
            findings.extend(self._run_osv_scanner(source_path, scan_id))

        findings.extend(self._scan_manifests(source_path, scan_id))

        seen = set()
        unique = []
        for f in findings:
            key = f"{f.file_path}:{f.title}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _run_pip_audit(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings = []
        req_files = list(source_path.rglob("requirements*.txt"))
        for req in req_files:
            cmd = ["pip-audit", "-r", str(req), "-f", "json"]
            res = self.run_command(cmd)
            if res and res.stdout:
                try:
                    data = json.loads(res.stdout)
                    rel_path = req.relative_to(source_path).as_posix()
                    for dep in data.get("dependencies", []):
                        for vuln in dep.get("vulns", []):
                            findings.append(Finding(
                                scan_id=scan_id,
                                title=f"Vulnerable Dependency: {dep.get('name')} ({vuln.get('id')})",
                                severity=Severity.HIGH,
                                category=Category.DEPENDENCY,
                                engine="pip-audit",
                                file_name=req.name,
                                file_path=rel_path,
                                description=vuln.get("description", "Vulnerability detected by pip-audit"),
                                evidence_redacted=f"{dep.get('name')}=={dep.get('version')}",
                                cwe="CWE-1395: Dependency on Vulnerable Third-Party Component",
                                owasp="A06:2021-Vulnerable and Outdated Components",
                                potential_impact="Known CVE vulnerability can be exploited by remote attackers.",
                                recommended_remediation=f"Upgrade {dep.get('name')} to safe version: {vuln.get('fix_versions', ['latest'])}",
                                reference_urls=[f"https://osv.dev/vulnerability/{vuln.get('id')}"] if vuln.get("id") else [],
                            ))
                except Exception as e:
                    logger.warning("Error parsing pip-audit output: %s", e)
        return findings

    def _run_osv_scanner(self, source_path: Path, scan_id: str) -> List[Finding]:
        cmd = ["osv-scanner", "--json", "-r", str(source_path)]
        res = self.run_command(cmd)
        findings = []
        if res and res.stdout:
            try:
                data = json.loads(res.stdout)
                for res_item in data.get("results", []):
                    pkg_source = res_item.get("source", {}).get("path", "")
                    rel_path = str(Path(pkg_source).as_posix()) if pkg_source else "manifest"
                    for pkg in res_item.get("packages", []):
                        pkg_info = pkg.get("package", {})
                        for vuln in pkg.get("vulnerabilities", []):
                            findings.append(Finding(
                                scan_id=scan_id,
                                title=f"Vulnerable Dependency: {pkg_info.get('name')} ({vuln.get('id')})",
                                severity=Severity.HIGH,
                                category=Category.DEPENDENCY,
                                engine="osv-scanner",
                                file_name=Path(rel_path).name,
                                file_path=rel_path,
                                description=vuln.get("summary", "Known vulnerability reported in OSV database."),
                                evidence_redacted=f"{pkg_info.get('name')}=={pkg_info.get('version')}",
                                cwe="CWE-1395: Dependency on Vulnerable Third-Party Component",
                                owasp="A06:2021-Vulnerable and Outdated Components",
                                potential_impact="Known security flaw in third party library.",
                                recommended_remediation=f"Upgrade package '{pkg_info.get('name')}' to a patched release.",
                                reference_urls=[f"https://osv.dev/vulnerability/{vuln.get('id')}"],
                            ))
            except Exception as e:
                logger.warning("Error parsing osv-scanner output: %s", e)
        return findings

    def _scan_manifests(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        for req_file in source_path.rglob("*requirement*.txt"):
            rel_path = req_file.relative_to(source_path).as_posix()
            content = self.safe_read_file(req_file)
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-.]+)\s*(?:==|<=|>=|<|>)\s*([0-9a-zA-Z_\-.]+)", line)
                if match:
                    pkg_name = match.group(1).lower()
                    pkg_version = match.group(2)
                    findings.extend(self._match_cve(pkg_name, pkg_version, "PyPI", rel_path, req_file.name, line, scan_id))

        for pkg_file in source_path.rglob("package.json"):
            rel_path = pkg_file.relative_to(source_path).as_posix()
            content = self.safe_read_file(pkg_file)
            try:
                data = json.loads(content)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for name, ver in deps.items():
                    clean_ver = re.sub(r"[^0-9.]", "", ver)
                    if clean_ver:
                        findings.extend(self._match_cve(name.lower(), clean_ver, "npm", rel_path, pkg_file.name, f'"{name}": "{ver}"', scan_id))
            except Exception:
                pass

        for pom_file in source_path.rglob("pom.xml"):
            rel_path = pom_file.relative_to(source_path).as_posix()
            content = self.safe_read_file(pom_file)
            dep_matches = re.findall(r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>", content)
            for artifact, ver in dep_matches:
                clean_ver = re.sub(r"[^0-9.]", "", ver)
                if clean_ver:
                    findings.extend(self._match_cve(artifact.lower(), clean_ver, "Maven", rel_path, pom_file.name, f"{artifact}:{ver}", scan_id))

        return findings

    def _match_cve(
        self,
        pkg: str,
        version: str,
        ecosystem: str,
        rel_path: str,
        file_name: str,
        evidence: str,
        scan_id: str,
    ) -> List[Finding]:
        results = []
        for rule in self.OFFLINE_CVE_DATABASE:
            if rule["package"] == pkg and rule["ecosystem"] == ecosystem:
                if self._is_version_lower(version, rule["vulnerable_below"]):
                    results.append(Finding(
                        scan_id=scan_id,
                        title=f"{rule['cve']} - {rule['title']}",
                        severity=rule["severity"],
                        category=Category.DEPENDENCY,
                        engine="dependency_engine",
                        file_name=file_name,
                        file_path=rel_path,
                        description=f"{rule['description']} Detected version: {version}. Affected versions: < {rule['vulnerable_below']}.",
                        evidence_redacted=evidence,
                        cwe="CWE-1395: Dependency on Vulnerable Third-Party Component",
                        owasp="A06:2021-Vulnerable and Outdated Components",
                        potential_impact="Exploitation of public CVE affecting application security, integrity, or availability.",
                        recommended_remediation=rule["remediation"],
                        reference_urls=[f"https://nvd.nist.gov/vuln/detail/{rule['cve']}"],
                    ))
        return results

    @staticmethod
    def _is_version_lower(v1_str: str, v2_str: str) -> bool:
        try:
            p1 = [int(x) for x in re.findall(r"\d+", v1_str)[:3]]
            p2 = [int(x) for x in re.findall(r"\d+", v2_str)[:3]]
            while len(p1) < 3:
                p1.append(0)
            while len(p2) < 3:
                p2.append(0)
            return p1 < p2
        except Exception:
            return False
