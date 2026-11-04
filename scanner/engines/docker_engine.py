"""
Docker Security Scanner
Integrates Trivy config scanning with a native CIS Docker Benchmark & Dockerfile static checker.
Detects root execution, embedded credentials, insecure base images, exposed ports, and privileged compose mounts.
"""

import json
import logging
from pathlib import Path
import re
import shutil
from typing import List

from scanner.engines.base import BaseEngine
from scanner.models import Finding, Severity, Category
from scanner.processing.redactor import Redactor

logger = logging.getLogger("scanner.engines.docker")


class DockerEngine(BaseEngine):
    """Scans Dockerfiles, container configs, and Docker Compose files for security anti-patterns."""

    engine_name: str = "trivy"

    def is_trivy_available(self) -> bool:
        return shutil.which("trivy") is not None

    def scan(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        if self.is_trivy_available():
            findings.extend(self._run_trivy(source_path, scan_id))

        findings.extend(self._scan_docker_files(source_path, scan_id))

        seen = set()
        unique = []
        for f in findings:
            key = f"{f.file_path}:{f.line_number}:{f.title}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _run_trivy(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings = []
        cmd = ["trivy", "config", "--format", "json", "--quiet", str(source_path)]
        res = self.run_command(cmd)
        if res and res.stdout:
            try:
                data = json.loads(res.stdout)
                for result_item in data.get("Results", []):
                    rel_target = result_item.get("Target", "Dockerfile")
                    for misconf in result_item.get("Misconfigurations", []):
                        raw_sev = misconf.get("Severity", "MEDIUM").upper()
                        sev = Severity.CRITICAL if raw_sev == "CRITICAL" else (
                            Severity.HIGH if raw_sev == "HIGH" else (
                                Severity.MEDIUM if raw_sev == "MEDIUM" else Severity.LOW
                            )
                        )
                        findings.append(Finding(
                            scan_id=scan_id,
                            title=f"Trivy: {misconf.get('Title', 'Container Misconfiguration')}",
                            severity=sev,
                            category=Category.DOCKER_SECURITY,
                            engine="trivy",
                            file_name=Path(rel_target).name,
                            file_path=rel_target,
                            line_number=misconf.get("CauseMetadata", {}).get("StartLine", 1),
                            description=misconf.get("Description", "Container configuration risk detected by Trivy."),
                            evidence_redacted=Redactor.mask_evidence(misconf.get("Message", "")),
                            cwe="CWE-1188: Insecure Default Initialization of Resource",
                            owasp="A05:2021-Security Misconfiguration",
                            potential_impact="Container compromise, privilege escalation, or host escape.",
                            recommended_remediation=misconf.get("Resolution", "Follow CIS Docker Benchmark guidance."),
                            reference_urls=misconf.get("References", []),
                        ))
            except Exception as e:
                logger.warning("Error parsing Trivy output: %s", e)
        return findings

    def _scan_docker_files(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        dockerfiles = []
        compose_files = []
        for p in source_path.rglob("*"):
            if not p.is_file():
                continue
            lower_name = p.name.lower()
            if "dockerfile" in lower_name:
                dockerfiles.append(p)
            elif lower_name in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
                compose_files.append(p)

        for df in dockerfiles:
            rel_path = df.relative_to(source_path).as_posix()
            content = self.safe_read_file(df)
            lines = content.splitlines()

            has_user_instruction = False
            has_healthcheck = False

            for line_idx, line in enumerate(lines, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue

                if re.match(r"^FROM\s+([^\s]+)", clean_line, re.IGNORECASE):
                    image_ref = re.match(r"^FROM\s+([^\s]+)", clean_line, re.IGNORECASE).group(1)
                    if ":" not in image_ref or image_ref.endswith(":latest"):
                        findings.append(Finding(
                            scan_id=scan_id,
                            title="Insecure Base Image: Unpinned or ':latest' Tag Used",
                            severity=Severity.MEDIUM,
                            category=Category.DOCKER_SECURITY,
                            engine="docker_engine",
                            file_name=df.name,
                            file_path=rel_path,
                            line_number=line_idx,
                            description=f"Base image '{image_ref}' does not use an immutable SHA-256 digest or pinned minor version.",
                            evidence_redacted=clean_line,
                            cwe="CWE-1188: Insecure Default Initialization of Resource",
                            owasp="A05:2021-Security Misconfiguration",
                            potential_impact="Build non-determinism, unexpected upstream security regressions, or supply chain poisoning.",
                            recommended_remediation="Pin base images to explicit versions or digests (e.g. python:3.12.3-slim-bookworm@sha256:...).",
                        ))

                if re.match(r"^ENV\s+.*(?:password|secret|key|token|auth)\s*=", clean_line, re.IGNORECASE):
                    findings.append(Finding(
                        scan_id=scan_id,
                        title="Hardcoded Secret in Dockerfile ENV Instruction",
                        severity=Severity.CRITICAL,
                        category=Category.DOCKER_SECURITY,
                        engine="docker_engine",
                        file_name=df.name,
                        file_path=rel_path,
                        line_number=line_idx,
                        description="ENV variables defined in Dockerfile are permanently baked into image metadata and layers.",
                        evidence_redacted=Redactor.mask_evidence(clean_line),
                        cwe="CWE-798: Use of Hard-coded Credentials",
                        owasp="A07:2021-Identification and Authentication Failures",
                        potential_impact="Anyone with access to the container image can view baked credentials via docker inspect.",
                        recommended_remediation="Inject secrets at runtime using docker run --env-file or Kubernetes Secrets.",
                    ))

                if re.search(r"^(?:COPY|ADD)\s+.*(?:\.env|id_rsa|id_dsa|\.pem|\.key)", clean_line, re.IGNORECASE):
                    findings.append(Finding(
                        scan_id=scan_id,
                        title="Baking Sensitive Files into Container Image (.env / private keys)",
                        severity=Severity.CRITICAL,
                        category=Category.DOCKER_SECURITY,
                        engine="docker_engine",
                        file_name=df.name,
                        file_path=rel_path,
                        line_number=line_idx,
                        description="Directly copying .env or private keys into container images exposes secrets in image layers.",
                        evidence_redacted=clean_line,
                        cwe="CWE-312: Cleartext Storage of Sensitive Information",
                        owasp="A01:2021-Broken Access Control",
                        potential_impact="Secrets become extractable by downloading or inspecting the container filesystem.",
                        recommended_remediation="Add .env and credential files to .dockerignore and mount secrets at runtime.",
                    ))

                if re.match(r"^EXPOSE\s+.*(?:22|2375|2376)", clean_line, re.IGNORECASE):
                    findings.append(Finding(
                        scan_id=scan_id,
                        title="Dangerous Port Exposed in Container (SSH / Docker Daemon)",
                        severity=Severity.HIGH,
                        category=Category.DOCKER_SECURITY,
                        engine="docker_engine",
                        file_name=df.name,
                        file_path=rel_path,
                        line_number=line_idx,
                        description="Exposing SSH (22) or Docker socket (2375/2376) inside containers violates least-privilege principles.",
                        evidence_redacted=clean_line,
                        cwe="CWE-272: Least Privilege Violation",
                        owasp="A05:2021-Security Misconfiguration",
                        potential_impact="Attackers can SSH into containers or execute root commands on the host via exposed Docker daemon.",
                        recommended_remediation="Remove port 22/2375. Use container orchestration exec (e.g. docker exec / kubectl exec) instead of SSH.",
                    ))

                if re.match(r"^USER\s+", clean_line, re.IGNORECASE):
                    has_user_instruction = True
                    if re.match(r"^USER\s+(?:root|0)\b", clean_line, re.IGNORECASE):
                        findings.append(Finding(
                            scan_id=scan_id,
                            title="Container Explicitly Configured to Run as Root",
                            severity=Severity.HIGH,
                            category=Category.DOCKER_SECURITY,
                            engine="docker_engine",
                            file_name=df.name,
                            file_path=rel_path,
                            line_number=line_idx,
                            description="Running containers as root maximizes the impact of container breakouts or remote code execution.",
                            evidence_redacted=clean_line,
                            cwe="CWE-250: Execution with Unnecessary Privileges",
                            owasp="A05:2021-Security Misconfiguration",
                            potential_impact="Container escape allows full root compromise of the host node.",
                            recommended_remediation="Define a non-root user (e.g. USER appuser) with UID >= 1000.",
                        ))

                if re.match(r"^HEALTHCHECK\s+", clean_line, re.IGNORECASE):
                    has_healthcheck = True

            if not has_user_instruction and len(lines) > 5:
                findings.append(Finding(
                    scan_id=scan_id,
                    title="Missing Non-Root USER Instruction in Dockerfile",
                    severity=Severity.MEDIUM,
                    category=Category.DOCKER_SECURITY,
                    engine="docker_engine",
                    file_name=df.name,
                    file_path=rel_path,
                    line_number=len(lines),
                    description="Dockerfile does not specify a USER instruction. Container will execute as root by default.",
                    evidence_redacted="USER instruction missing",
                    cwe="CWE-250: Execution with Unnecessary Privileges",
                    owasp="A05:2021-Security Misconfiguration",
                    potential_impact="Default execution as root elevates blast radius if the application is exploited.",
                    recommended_remediation="Add a non-root user: RUN useradd -u 10001 appuser && USER appuser.",
                ))

        for cf in compose_files:
            rel_path = cf.relative_to(source_path).as_posix()
            content = self.safe_read_file(cf)
            lines = content.splitlines()

            for line_idx, line in enumerate(lines, start=1):
                clean_line = line.strip()
                if re.search(r"privileged\s*:\s*true", clean_line, re.IGNORECASE):
                    findings.append(Finding(
                        scan_id=scan_id,
                        title="Docker Compose: Privileged Container Execution Enabled",
                        severity=Severity.CRITICAL,
                        category=Category.DOCKER_SECURITY,
                        engine="docker_engine",
                        file_name=cf.name,
                        file_path=rel_path,
                        line_number=line_idx,
                        description="'privileged: true' grants container access to all host devices and disables kernel capabilities security.",
                        evidence_redacted=clean_line,
                        cwe="CWE-250: Execution with Unnecessary Privileges",
                        owasp="A05:2021-Security Misconfiguration",
                        potential_impact="Immediate container breakout to the host operating system.",
                        recommended_remediation="Remove privileged: true and grant only explicit Linux capabilities via cap_add.",
                    ))

                if re.search(r"/var/run/docker\.sock", clean_line):
                    findings.append(Finding(
                        scan_id=scan_id,
                        title="Docker Compose: Host Docker Socket Mounted (/var/run/docker.sock)",
                        severity=Severity.CRITICAL,
                        category=Category.DOCKER_SECURITY,
                        engine="docker_engine",
                        file_name=cf.name,
                        file_path=rel_path,
                        line_number=line_idx,
                        description="Mounting /var/run/docker.sock grants container root-level control over the host Docker daemon.",
                        evidence_redacted=clean_line,
                        cwe="CWE-250: Execution with Unnecessary Privileges",
                        owasp="A05:2021-Security Misconfiguration",
                        potential_impact="Full takeover of the host by creating privileged sibling containers.",
                        recommended_remediation="Avoid mounting docker.sock. Use isolated API proxies with scoped permissions.",
                    ))

        return findings
