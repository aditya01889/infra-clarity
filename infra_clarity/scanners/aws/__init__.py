"""AWS resource scanners for Infra Clarity."""
from typing import List, Optional
from rich.console import Console
from rich.progress import Progress

from ...core.models import Finding, ScanResult, Severity, ResourceType
from .base_scanner import AWSScanner
from .ec2_scanner import EC2Scanner
from .s3_scanner import S3Scanner

console = Console()

class AWSScannerManager(AWSScanner):
    """Manages multiple AWS service scanners."""
    
    def __init__(self, profile: Optional[str] = None, region: str = 'us-east-1'):
        """Initialize the AWS scanner manager.
        
        Args:
            profile: Optional AWS profile name
            region: AWS region to scan (default: us-east-1)
        """
        super().__init__(profile, region)
        self.scanners = [
            EC2Scanner(profile, region),
            S3Scanner(profile, region)
            # Add more scanners here as they're implemented
        ]
    
    def scan(self) -> ScanResult:
        """Run all AWS scanners and return combined results."""
        if not self._check_credentials():
            return self.results
        
        with Progress() as progress:
            task = progress.add_task("Scanning AWS resources...", total=len(self.scanners))
            
            for scanner in self.scanners:
                scanner_name = scanner.__class__.__name__.replace('Scanner', '')
                progress.update(task, description=f"Scanning {scanner_name}...")
                
                try:
                    scanner_results = scanner.scan()
                    for finding in scanner_results.findings:
                        self.results.add_finding(finding)
                except Exception as e:
                    self._add_finding(
                        resource_id=f"{scanner_name.lower()}-scan",
                        resource_type=ResourceType.IAM,  # Default to IAM for scanner errors
                        finding_type=f"{scanner_name}ScanError",
                        severity=Severity.MEDIUM,
                        message=f"Error during {scanner_name} scan: {str(e)}",
                        details={"error": str(e)},
                        remediation="Check AWS permissions and try again"
                    )
                
                progress.advance(task)
        
        return self.results

# For backward compatibility
AWSScanner = AWSScannerManager
