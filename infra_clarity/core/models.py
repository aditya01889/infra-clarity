"""Core data models for Infra Clarity."""
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ResourceType(str, Enum):
    """Supported AWS resource types."""
    UNKNOWN = "unknown"
    EC2 = "ec2"
    S3 = "s3"
    RDS = "rds"
    IAM = "iam"
    SECURITY_GROUP = "security_group"
    EBS = "ebs"
    LAMBDA = "lambda"
    CLOUDFRONT = "cloudfront"


class Finding(BaseModel):
    """A single finding from the scanner."""
    resource_id: str = Field(..., description="The unique identifier of the resource")
    resource_type: ResourceType = Field(..., description="Type of the resource")
    finding_type: str = Field(..., description="Type of the finding")
    severity: Severity = Field(..., description="Severity of the finding")
    message: str = Field(..., description="Human-readable description")
    details: Dict = Field(default_factory=dict, description="Additional details")
    remediation: Optional[str] = Field(None, description="Suggested remediation steps")


class ScanResult(BaseModel):
    """Container for scan results."""
    findings: List[Finding] = Field(default_factory=list)
    metadata: Dict = Field(default_factory=dict)
    
    def add_finding(self, finding: Finding) -> None:
        """Add a new finding to the scan results."""
        self.findings.append(finding)
    
    @property
    def critical_findings(self) -> List[Finding]:
        """Get all critical findings."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]
    
    @property
    def high_findings(self) -> List[Finding]:
        """Get all high severity findings."""
        return [f for f in self.findings if f.severity == Severity.HIGH]
    
    @property
    def medium_findings(self) -> List[Finding]:
        """Get all medium severity findings."""
        return [f for f in self.findings if f.severity == Severity.MEDIUM]
    
    @property
    def low_findings(self) -> List[Finding]:
        """Get all low severity findings."""
        return [f for f in self.findings if f.severity == Severity.LOW]
    
    @property
    def info_findings(self) -> List[Finding]:
        """Get all informational findings."""
        return [f for f in self.findings if f.severity == Severity.INFO]
