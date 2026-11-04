"""
Base Security Scanning Engine Interface
"""

from abc import ABC, abstractmethod
import logging
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional

from scanner.config import ScannerConfig
from scanner.models import Finding

logger = logging.getLogger("scanner.engines.base")


class BaseEngine(ABC):
    """Abstract base class that all security detection modules must implement."""

    engine_name: str = "base_engine"

    @abstractmethod
    def scan(self, source_path: Path, scan_id: str) -> List[Finding]:
        """
        Executes security scanning against the target source directory.
        Must return a list of Finding objects.
        """
        raise NotImplementedError

    def is_available(self) -> bool:
        """Returns True if the underlying tool or engine is ready."""
        return True

    def find_files_by_extensions(self, root_dir: Path, extensions: set) -> List[Path]:
        """Recursively discovers files matching specified extensions, avoiding ignored paths."""
        matched = []
        ignored_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode"}
        for path in root_dir.rglob("*"):
            if path.is_file():
                if any(ignored in path.parts for ignored in ignored_dirs):
                    continue
                if path.suffix.lower() in extensions or path.name.lower() in extensions:
                    matched.append(path)
        return matched

    def safe_read_file(self, file_path: Path, max_bytes: int = 10 * 1024 * 1024) -> str:
        """Reads file content safely with UTF-8 and fallback encoding."""
        try:
            if file_path.stat().st_size > max_bytes:
                return ""
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            logger.debug("Failed reading file %s: %s", file_path, e)
            return ""

    def run_command(
        self,
        cmd: List[str],
        timeout: int = ScannerConfig.ENGINE_TIMEOUT_SECONDS,
        cwd: Optional[Path] = None,
    ) -> Optional[subprocess.CompletedProcess]:
        """Executes a command safely with timeout handling."""
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(cwd) if cwd else None,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Command %s timed out after %s seconds.", cmd[0], timeout)
            return None
        except FileNotFoundError:
            logger.debug("Command binary %s not found on PATH.", cmd[0])
            return None
        except Exception as e:
            logger.warning("Unexpected error running %s: %s", cmd[0], e)
            return None
