"""
Repository Manager
Safely validates and clones remote Git repositories with SSRF protection,
shallow cloning, strict timeouts, and disabled git hooks execution.
"""

import ipaddress
import logging
from pathlib import Path
import re
import socket
import subprocess
from typing import Optional
from urllib.parse import urlparse

from scanner.config import ScannerConfig
from scanner.ingestion.upload_manager import UploadManager

logger = logging.getLogger("scanner.ingestion.repository")


class RepositorySecurityException(Exception):
    """Raised when repository cloning violates security constraints or SSRF rules."""
    pass


class RepositoryManager:
    """Manages cloning and sanitization of remote Git repositories."""

    BLOCKED_NETWORKS = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),       # AWS/Cloud Metadata & Link-local
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    @classmethod
    def validate_repository_url(cls, repo_url: str) -> None:
        """
        Validates the repository URL and defends against SSRF attacks targeting
        internal networks and cloud metadata services.
        """
        if not repo_url or not isinstance(repo_url, str):
            raise RepositorySecurityException("Repository URL cannot be empty.")

        parsed = urlparse(repo_url.strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            raise RepositorySecurityException(
                f"Unsupported URL scheme '{parsed.scheme}'. Only HTTPS and HTTP repositories are permitted."
            )

        hostname = parsed.hostname
        if not hostname:
            raise RepositorySecurityException("Invalid repository URL: Missing hostname.")

        # Resolve IP and verify it is not in blocked private / metadata ranges
        try:
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
            for blocked in cls.BLOCKED_NETWORKS:
                if ip_obj in blocked:
                    raise RepositorySecurityException(
                        f"SSRF violation: Host '{hostname}' resolves to blocked private/internal IP {ip_str}."
                    )
        except socket.gaierror:
            # If domain cannot be resolved immediately, allow only public domains
            if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", hostname):
                raise RepositorySecurityException(f"Unresolvable or invalid repository host: {hostname}")

    @classmethod
    def clone_repository(
        cls,
        repo_url: str,
        scan_id: str,
        branch: Optional[str] = None,
        fetch_history: bool = False,
    ) -> Path:
        """
        Clones a remote repository into an isolated sandbox workspace.
        Uses depth 1 by default, disables hook execution, and enforces strict timeout.
        """
        cls.validate_repository_url(repo_url)

        workspace = UploadManager.create_sandbox_workspace(scan_id)
        target_dir = workspace / "source"
        target_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "git",
            "clone",
            "--config",
            "core.hooksPath=/dev/null",  # Prevent malicious hook execution
        ]

        if not fetch_history:
            cmd.extend(["--depth", "1"])

        if branch:
            cmd.extend(["--branch", branch])

        cmd.extend([repo_url, str(target_dir)])

        # Redact credentials in logs if URL contained basic auth
        sanitized_url = re.sub(r"://[^@]+@", "://***:***@", repo_url)
        logger.info("Cloning repository %s into sandbox %s...", sanitized_url, target_dir)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=ScannerConfig.GIT_CLONE_TIMEOUT_SECONDS,
                check=False,
            )
            if result.returncode != 0:
                err_msg = result.stderr.strip()
                # Sanitize any credentials from error output
                sanitized_err = re.sub(r"://[^@]+@", "://***:***@", err_msg)
                raise RepositorySecurityException(f"Git clone failed: {sanitized_err}")

        except subprocess.TimeoutExpired:
            raise RepositorySecurityException(
                f"Git clone timed out after {ScannerConfig.GIT_CLONE_TIMEOUT_SECONDS} seconds."
            )
        except FileNotFoundError:
            raise RepositorySecurityException("Git binary not found on system PATH.")

        return target_dir
