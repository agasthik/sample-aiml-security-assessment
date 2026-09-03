from enum import Enum
import re
from typing import Any, Dict

from pydantic import BaseModel, Field, field_validator


class SeverityEnum(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class StatusEnum(str, Enum):
    FAILED = "Failed"
    PASSED = "Passed"
    NA = "N/A"


class Finding(BaseModel):
    """Represents a security finding with the shared report CSV schema."""

    Check_ID: str = Field(..., min_length=1)
    Finding: str = Field(..., min_length=1)
    Finding_Details: str = Field(..., min_length=1)
    Resolution: str = Field(..., min_length=0)
    Reference: str
    Severity: SeverityEnum
    Status: StatusEnum
    Region: str = ""

    @field_validator("Check_ID")
    @classmethod
    def validate_check_id(cls, value: str) -> str:
        if not re.match(r"^[A-Z]{2,3}-\d{2}$", value):
            raise ValueError("Check_ID must follow pattern XX-NN (e.g., AR-01)")
        return value

    @field_validator("Reference")
    @classmethod
    def validate_reference_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("Reference URL must start with https://")
        return value


def create_finding(
    check_id: str,
    finding_name: str,
    finding_details: str,
    resolution: str,
    reference: str,
    severity: SeverityEnum,
    status: StatusEnum,
    region: str = "",
) -> Dict[str, Any]:
    """Create a validated finding in the shared CSV schema."""
    return dict(
        Finding(
            Check_ID=check_id,
            Finding=finding_name,
            Finding_Details=finding_details,
            Resolution=resolution,
            Reference=reference,
            Severity=severity,
            Status=status,
            Region=region,
        ).model_dump()
    )
