"""
Data Models and Enums for Universal Security Scanner
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    SECRET_LEAK = "SECRET_LEAK"
    SAST_VULNERABILITY = "SAST_VULNERABILITY"
    DEPENDENCY = "DEPENDENCY"
    DOCKER_SECURITY = "DOCKER_SECURITY"
    GIT_HISTORY = "GIT_HISTORY"


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    INGESTING = "INGESTING"
    SCANNING = "SCANNING"
    NORMALIZING = "NORMALIZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class SourceType(str, Enum):
    LOCAL_FOLDER = "LOCAL_FOLDER"
    ZIP_UPLOAD = "ZIP_UPLOAD"
    GITHUB_REPO = "GITHUB_REPO"
    DOCKERFILE = "DOCKERFILE"
    SINGLE_FILE = "SINGLE_FILE"


@dataclass
class Finding:
    """Represents a single normalized security finding."""
    finding_id: str = field(default_factory=lambda: f"fnd_{uuid.uuid4().hex[:12]}")
    scan_id: str = ""
    project_name: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    category: Category = Category.SAST_VULNERABILITY
    engine: str = ""
    file_name: str = ""
    file_path: str = ""
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    description: str = ""
    evidence_redacted: str = ""
    cwe: str = ""
    owasp: str = ""
    potential_impact: str = ""
    recommended_remediation: str = ""
    reference_urls: List[str] = field(default_factory=list)
    fingerprint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        data["category"] = self.category.value if isinstance(self.category, Category) else str(self.category)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        d = dict(data)
        if "severity" in d and isinstance(d["severity"], str):
            d["severity"] = Severity(d["severity"])
        if "category" in d and isinstance(d["category"], str):
            d["category"] = Category(d["category"])
        return cls(**d)


@dataclass
class ScanSummary:
    """Statistical summary of findings for a single scan."""
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    secrets_count: int = 0
    sast_count: int = 0
    dependencies_count: int = 0
    docker_count: int = 0
    git_history_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanRecord:
    """Represents a complete security scan job."""
    scan_id: str = field(default_factory=lambda: f"scan_{uuid.uuid4().hex[:12]}")
    project_name: str = "Untrusted-Project"
    source_type: SourceType = SourceType.LOCAL_FOLDER
    source_target: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    status: ScanStatus = ScanStatus.QUEUED
    progress_percentage: int = 0
    current_engine: str = ""
    risk_score: float = 0.0  # 0 to 100
    security_grade: str = "A"  # A+, A, B, C, D, F
    summary: ScanSummary = field(default_factory=ScanSummary)
    engines_executed: List[str] = field(default_factory=list)
    user_id: str = "anonymous"
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["source_type"] = self.source_type.value if isinstance(self.source_type, SourceType) else str(self.source_type)
        data["status"] = self.status.value if isinstance(self.status, ScanStatus) else str(self.status)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanRecord":
        d = dict(data)
        if "source_type" in d and isinstance(d["source_type"], str):
            d["source_type"] = SourceType(d["source_type"])
        if "status" in d and isinstance(d["status"], str):
            d["status"] = ScanStatus(d["status"])
        if "summary" in d and isinstance(d["summary"], dict):
            d["summary"] = ScanSummary(**d["summary"])
        return cls(**d)
