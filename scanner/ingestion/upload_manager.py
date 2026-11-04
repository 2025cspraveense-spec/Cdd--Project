"""
Upload Manager
Safely validates and extracts archives, enforces size and decompression quotas,
and prevents Zip Slip / path traversal vulnerabilities.
"""

import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Optional, Tuple
import zipfile

from scanner.config import ScannerConfig


class UploadSecurityException(Exception):
    """Raised when an archive violates security constraints."""
    pass


class UploadManager:
    """Manages untrusted user uploads and local folder containment."""

    @staticmethod
    def create_sandbox_workspace(scan_id: str) -> Path:
        """Create a dedicated ephemeral workspace for a scan job."""
        workspace = ScannerConfig.WORKSPACE_ROOT / scan_id
        workspace.mkdir(parents=True, exist_ok=True)
        return workspace

    @classmethod
    def process_zip_upload(cls, archive_path: Path, scan_id: str) -> Path:
        """
        Safely extracts an uploaded ZIP archive into an isolated sandbox workspace.
        Applies Zip Slip prevention and Zip Bomb decompression limits.
        """
        workspace = cls.create_sandbox_workspace(scan_id)
        extract_dir = workspace / "source"
        extract_dir.mkdir(parents=True, exist_ok=True)

        # 1. Enforce archive file size
        archive_size = archive_path.stat().st_size
        max_bytes = ScannerConfig.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        if archive_size > max_bytes:
            raise UploadSecurityException(
                f"Archive size ({archive_size / (1024*1024):.1f} MB) exceeds limit ({ScannerConfig.MAX_UPLOAD_SIZE_MB} MB)"
            )

        total_uncompressed_bytes = 0
        total_files = 0
        max_uncompressed = ScannerConfig.MAX_UNCOMPRESSED_SIZE_MB * 1024 * 1024

        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                for member in zf.infolist():
                    total_files += 1
                    if total_files > ScannerConfig.MAX_ARCHIVE_FILES:
                        raise UploadSecurityException(
                            f"Archive file count ({total_files}) exceeds limit ({ScannerConfig.MAX_ARCHIVE_FILES})"
                        )

                    total_uncompressed_bytes += member.file_size
                    if total_uncompressed_bytes > max_uncompressed:
                        raise UploadSecurityException(
                            f"Total uncompressed size exceeds safe threshold ({ScannerConfig.MAX_UNCOMPRESSED_SIZE_MB} MB)"
                        )

                    # Zip Slip Mitigation: Canonical path checking
                    target_path = (extract_dir / member.filename).resolve()
                    if not str(target_path).startswith(str(extract_dir.resolve())):
                        raise UploadSecurityException(
                            f"Zip Slip attack detected in member: '{member.filename}'"
                        )

                    # Strip execution permissions for safety
                    zf.extract(member, extract_dir)
                    if target_path.is_file():
                        try:
                            os.chmod(target_path, 0o644)
                        except Exception:
                            pass

        except zipfile.BadZipFile as e:
            raise UploadSecurityException(f"Invalid or corrupted ZIP archive: {e}")

        return extract_dir

    @classmethod
    def process_single_file(cls, filename: str, content: bytes, scan_id: str) -> Path:
        """Saves a single uploaded source file or Dockerfile into the workspace."""
        workspace = cls.create_sandbox_workspace(scan_id)
        source_dir = workspace / "source"
        source_dir.mkdir(parents=True, exist_ok=True)

        safe_filename = Path(filename).name
        target = source_dir / safe_filename
        with open(target, "wb") as f:
            f.write(content)

        return source_dir

    @classmethod
    def process_local_folder(cls, local_path: str, scan_id: str) -> Path:
        """
        Validates a local folder path and creates a read-only mirror snapshot
        in the sandbox workspace to ensure the original source code is NEVER modified.
        """
        source_folder = Path(local_path).resolve()
        if not source_folder.exists() or not source_folder.is_dir():
            raise UploadSecurityException(f"Local folder path does not exist or is not a directory: {local_path}")

        workspace = cls.create_sandbox_workspace(scan_id)
        dest_dir = workspace / "source"

        # Safely copy files, excluding heavy/unrelated directories (.git, node_modules, __pycache__)
        def ignore_patterns(folder, contents):
            ignored = set()
            for name in contents:
                if name in {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode"}:
                    ignored.add(name)
            return ignored

        shutil.copytree(source_folder, dest_dir, ignore=ignore_patterns, dirs_exist_ok=True)
        return dest_dir

    @classmethod
    def cleanup_workspace(cls, scan_id: str) -> None:
        """Deletes ephemeral scan workspace completely."""
        workspace = ScannerConfig.WORKSPACE_ROOT / scan_id
        if workspace.exists():
            try:
                shutil.rmtree(workspace, ignore_errors=True)
            except Exception:
                pass
