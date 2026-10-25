"""
Defines severity levels, confidence categories, and Finding data classes
for defensive SQL Injection vulnerability assessments.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, List, Optional
import datetime


class Severity(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Confidence(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CONFIRMED = "Confirmed"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    endpoint: str
    parameter: Optional[str]
    description: str
    evidence: str
    remediation: str
    secure_code_example: str
    verification_steps: str
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    dbms_detected: Optional[str] = None
    technical_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        return data
