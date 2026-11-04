"""
Static Analysis Security Testing (SAST) Engine
Integrates Semgrep and Bandit CLI with a native Python AST & regex vulnerability analyzer.
Detects SQLi, XSS, Command Injection, Path Traversal, Insecure Deserialization,
Weak Crypto, Unsafe Uploads, and Hardcoded Keys.
"""

import ast
import json
import logging
from pathlib import Path
import re
import shutil
from typing import Any, List

from scanner.engines.base import BaseEngine
from scanner.models import Finding, Severity, Category
from scanner.processing.redactor import Redactor

logger = logging.getLogger("scanner.engines.sast")


class SASTEngine(BaseEngine):
    """Static Application Security Testing Engine for multi-language codebases."""

    engine_name: str = "sast_engine"

    def is_semgrep_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def is_bandit_available(self) -> bool:
        return shutil.which("bandit") is not None

    def scan(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        if self.is_semgrep_available():
            findings.extend(self._run_semgrep(source_path, scan_id))

        if self.is_bandit_available():
            findings.extend(self._run_bandit(source_path, scan_id))

        findings.extend(self._run_native_sast(source_path, scan_id))

        seen = set()
        unique = []
        for f in findings:
            key = f"{f.file_path}:{f.line_number}:{f.title}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _run_semgrep(self, source_path: Path, scan_id: str) -> List[Finding]:
        cmd = ["semgrep", "--config=p/security-audit", "--json", "--quiet", str(source_path)]
        res = self.run_command(cmd)
        findings = []
        if res and res.stdout:
            try:
                data = json.loads(res.stdout)
                for item in data.get("results", []):
                    sev = Severity.HIGH
                    raw_sev = item.get("extra", {}).get("severity", "").upper()
                    if raw_sev == "ERROR":
                        sev = Severity.CRITICAL
                    elif raw_sev == "WARNING":
                        sev = Severity.HIGH
                    elif raw_sev == "INFO":
                        sev = Severity.MEDIUM

                    rel_path = str(Path(item.get("path", "")).as_posix())
                    line_no = item.get("start", {}).get("line", 1)
                    code_snippet = item.get("extra", {}).get("lines", "")

                    f = Finding(
                        scan_id=scan_id,
                        title=item.get("check_id", "Semgrep Security Finding"),
                        severity=sev,
                        category=Category.SAST_VULNERABILITY,
                        engine="semgrep",
                        file_name=Path(rel_path).name,
                        file_path=rel_path,
                        line_number=line_no,
                        description=item.get("extra", {}).get("message", "Vulnerability detected by Semgrep"),
                        evidence_redacted=Redactor.mask_evidence(code_snippet),
                        cwe=item.get("extra", {}).get("metadata", {}).get("cwe", ["CWE-20: Improper Input Validation"])[0] if isinstance(item.get("extra", {}).get("metadata", {}).get("cwe"), list) else "CWE-20",
                        owasp=item.get("extra", {}).get("metadata", {}).get("owasp", ["A03:2021-Injection"])[0] if isinstance(item.get("extra", {}).get("metadata", {}).get("owasp"), list) else "A03:2021-Injection",
                        potential_impact="Application vulnerability permitting unauthorized operations or data compromise.",
                        recommended_remediation="Refactor code according to OWASP secure coding guidelines.",
                    )
                    findings.append(f)
            except Exception as e:
                logger.warning("Error parsing Semgrep results: %s", e)
        return findings

    def _run_bandit(self, source_path: Path, scan_id: str) -> List[Finding]:
        cmd = ["bandit", "-r", str(source_path), "-f", "json", "-q"]
        res = self.run_command(cmd)
        findings = []
        if res and res.stdout:
            try:
                data = json.loads(res.stdout)
                for item in data.get("results", []):
                    b_sev = item.get("issue_severity", "MEDIUM").upper()
                    sev = Severity.CRITICAL if b_sev == "HIGH" else (Severity.HIGH if b_sev == "MEDIUM" else Severity.MEDIUM)
                    rel_path = str(Path(item.get("filename", "")).as_posix())

                    f = Finding(
                        scan_id=scan_id,
                        title=f"Bandit: {item.get('test_name', 'Security Issue')}",
                        severity=sev,
                        category=Category.SAST_VULNERABILITY,
                        engine="bandit",
                        file_name=Path(rel_path).name,
                        file_path=rel_path,
                        line_number=item.get("line_number"),
                        description=item.get("issue_text", ""),
                        evidence_redacted=Redactor.mask_evidence(item.get("code", "")),
                        cwe=f"CWE-{item.get('issue_cwe', {}).get('id', '20')}",
                        owasp="A03:2021-Injection",
                        potential_impact="Insecure code construct identified in Python source.",
                        recommended_remediation="Address Bandit static analysis recommendations.",
                    )
                    findings.append(f)
            except Exception as e:
                logger.warning("Error parsing Bandit results: %s", e)
        return findings

    def _run_native_sast(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Python AST Scanning
        py_files = self.find_files_by_extensions(source_path, {".py"})
        for py_path in py_files:
            rel_path = py_path.relative_to(source_path).as_posix()
            content = self.safe_read_file(py_path)
            if not content:
                continue
            try:
                tree = ast.parse(content, filename=str(py_path))
                visitor = PythonASTSecurityVisitor(scan_id, rel_path, py_path.name, content.splitlines())
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # 2. Multi-language Regex SAST Scanning
        other_files = self.find_files_by_extensions(source_path, {".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".go"})
        for other_path in other_files:
            rel_path = other_path.relative_to(source_path).as_posix()
            content = self.safe_read_file(other_path)
            if not content:
                continue
            lines = content.splitlines()
            for line_idx, line in enumerate(lines, start=1):
                if re.search(r"(?:innerHTML\s*=|dangerouslySetInnerHTML|document\.write\()", line):
                    findings.append(Finding(
                        scan_id=scan_id,
                        title="Cross-Site Scripting (XSS): Unsafe DOM Manipulation",
                        severity=Severity.HIGH,
                        category=Category.SAST_VULNERABILITY,
                        engine="sast_engine",
                        file_name=other_path.name,
                        file_path=rel_path,
                        line_number=line_idx,
                        description="Direct insertion of untrusted data into innerHTML or document.write can lead to Stored/Reflected XSS.",
                        evidence_redacted=Redactor.mask_evidence(line),
                        cwe="CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                        owasp="A03:2021-Injection",
                        potential_impact="Attackers can execute arbitrary JavaScript in the victim's browser, hijacking sessions or stealing tokens.",
                        recommended_remediation="Use textContent or framework data-binding with automatic contextual HTML escaping.",
                    ))

                if re.search(r'(?:exec|spawn)\s*\([^)]*(?:\+|`|\$\{)', line):
                    findings.append(Finding(
                        scan_id=scan_id,
                        title="Potential OS Command Injection (Unsanitized Subprocess)",
                        severity=Severity.CRITICAL,
                        category=Category.SAST_VULNERABILITY,
                        engine="sast_engine",
                        file_name=other_path.name,
                        file_path=rel_path,
                        line_number=line_idx,
                        description="Dynamic string concatenation inside process execution allows attackers to append arbitrary shell commands.",
                        evidence_redacted=Redactor.mask_evidence(line),
                        cwe="CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                        owasp="A03:2021-Injection",
                        potential_impact="Full remote code execution (RCE) on the host operating system.",
                        recommended_remediation="Use execFile with argument arrays instead of running through a shell interpreter.",
                    ))

        return findings


class PythonASTSecurityVisitor(ast.NodeVisitor):
    """Inspects Python Abstract Syntax Trees for critical security anti-patterns."""

    def __init__(self, scan_id: str, file_path: str, file_name: str, lines: List[str]):
        self.scan_id = scan_id
        self.file_path = file_path
        self.file_name = file_name
        self.lines = lines
        self.findings: List[Finding] = []

    def _get_line_snippet(self, line_no: int) -> str:
        if 1 <= line_no <= len(self.lines):
            return self.lines[line_no - 1]
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_func_name(node.func)
        line_no = getattr(node, "lineno", 1)
        evidence = self._get_line_snippet(line_no)

        if any(sink in func_name for sink in ["execute", "executemany", "raw_query"]):
            if node.args and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr)):
                self.findings.append(Finding(
                    scan_id=self.scan_id,
                    title="SQL Injection: Dynamic Query Formatting Detected",
                    severity=Severity.CRITICAL,
                    category=Category.SAST_VULNERABILITY,
                    engine="sast_engine",
                    file_name=self.file_name,
                    file_path=self.file_path,
                    line_number=line_no,
                    description="SQL query is constructed using string concatenation or f-strings instead of parameterized queries.",
                    evidence_redacted=Redactor.mask_evidence(evidence),
                    cwe="CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                    owasp="A03:2021-Injection",
                    potential_impact="Unauthorized reading, tampering, or deletion of database contents, authentication bypass.",
                    recommended_remediation="Rewrite using parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)).",
                    reference_urls=["https://owasp.org/Top10/A03_2021-Injection/"],
                ))

        if func_name in ["os.system", "os.popen", "commands.getoutput"] or (
            "subprocess" in func_name and any(
                isinstance(kw, ast.keyword) and kw.arg == "shell" and getattr(kw.value, "value", False) is True
                for kw in node.keywords
            )
        ):
            self.findings.append(Finding(
                scan_id=self.scan_id,
                title="OS Command Injection: Unsafe Shell Execution",
                severity=Severity.CRITICAL,
                category=Category.SAST_VULNERABILITY,
                engine="sast_engine",
                file_name=self.file_name,
                file_path=self.file_path,
                line_number=line_no,
                description=f"Invocation of '{func_name}' with shell execution enables arbitrary system command execution.",
                evidence_redacted=Redactor.mask_evidence(evidence),
                cwe="CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                owasp="A03:2021-Injection",
                potential_impact="Complete server compromise and remote arbitrary code execution.",
                recommended_remediation="Pass command arguments as a list with shell=False (default in subprocess.run).",
            ))

        if func_name in ["pickle.loads", "pickle.load", "_pickle.loads", "marshal.loads", "shelve.open"]:
            self.findings.append(Finding(
                scan_id=self.scan_id,
                title="Insecure Deserialization via Python Pickle",
                severity=Severity.CRITICAL,
                category=Category.SAST_VULNERABILITY,
                engine="sast_engine",
                file_name=self.file_name,
                file_path=self.file_path,
                line_number=line_no,
                description="Deserializing untrusted pickle streams allows arbitrary object instantiation and code execution.",
                evidence_redacted=Redactor.mask_evidence(evidence),
                cwe="CWE-502: Deserialization of Untrusted Data",
                owasp="A08:2021-Software and Data Integrity Failures",
                potential_impact="Arbitrary code execution on the server running deserialization.",
                recommended_remediation="Use secure serialization formats like JSON, Protocol Buffers, or HMAC-authenticated payloads.",
            ))

        if func_name in ["hashlib.md5", "hashlib.sha1", "Crypto.Cipher.DES.new", "Crypto.Cipher.ARC4.new"]:
            self.findings.append(Finding(
                scan_id=self.scan_id,
                title="Broken or Deprecated Cryptographic Algorithm",
                severity=Severity.MEDIUM,
                category=Category.SAST_VULNERABILITY,
                engine="sast_engine",
                file_name=self.file_name,
                file_path=self.file_path,
                line_number=line_no,
                description=f"Usage of broken cryptographic function '{func_name}'. MD5, SHA-1, and DES are vulnerable to collision attacks.",
                evidence_redacted=Redactor.mask_evidence(evidence),
                cwe="CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                owasp="A02:2021-Cryptographic Failures",
                potential_impact="Hash collision and credential forgery.",
                recommended_remediation="Upgrade to SHA-256 / SHA-3 for hashing and AES-GCM for symmetric encryption.",
            ))

        if func_name == "open" and node.args and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr)):
            self.findings.append(Finding(
                scan_id=self.scan_id,
                title="Potential Path Traversal via Unvalidated File Path",
                severity=Severity.HIGH,
                category=Category.SAST_VULNERABILITY,
                engine="sast_engine",
                file_name=self.file_name,
                file_path=self.file_path,
                line_number=line_no,
                description="Dynamic file path construction without canonicalization can allow access to arbitrary system files.",
                evidence_redacted=Redactor.mask_evidence(evidence),
                cwe="CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                owasp="A01:2021-Broken Access Control",
                potential_impact="Unauthorized reading or overwriting of sensitive server files (/etc/passwd, configuration files).",
                recommended_remediation="Validate that the resolved absolute path starts with the intended base directory using os.path.commonpath.",
            ))

        if "save" in func_name and "file" in func_name.lower():
            if evidence and "secure_filename" not in evidence:
                self.findings.append(Finding(
                    scan_id=self.scan_id,
                    title="Unrestricted / Unsafe File Upload",
                    severity=Severity.HIGH,
                    category=Category.SAST_VULNERABILITY,
                    engine="sast_engine",
                    file_name=self.file_name,
                    file_path=self.file_path,
                    line_number=line_no,
                    description="Saving an uploaded file without sanitizing file.filename allows path traversal or arbitrary file upload.",
                    evidence_redacted=Redactor.mask_evidence(evidence),
                    cwe="CWE-434: Unrestricted Upload of File with Dangerous Type",
                    owasp="A04:2021-Insecure Design",
                    potential_impact="Upload of executable scripts leading to remote code execution.",
                    recommended_remediation="Use werkzeug.utils.secure_filename and validate file extension against an allowlist.",
                ))

        self.generic_visit(node)

    @staticmethod
    def _resolve_func_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val_name = PythonASTSecurityVisitor._resolve_func_name(node.value)
            return f"{val_name}.{node.attr}" if val_name else node.attr
        return ""
