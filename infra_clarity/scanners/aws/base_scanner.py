"""Base AWS scanner class."""
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from rich.console import Console

from ...core.models import Finding, ScanResult, Severity, ResourceType

console = Console()

class AWSScanner:
    """Base class for AWS resource scanners."""
    
    def __init__(self, profile: Optional[str] = None, region: str = 'us-east-1'):
        """Initialize the AWS scanner.
        
        Args:
            profile: Optional AWS profile name
            region: AWS region to scan (default: us-east-1)
        """
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.results = ScanResult()
        self.region = region
    
    def scan(self) -> ScanResult:
        """Run the scanner and return results.
        
        Returns:
            ScanResult: The scan results
        """
        raise NotImplementedError("Subclasses must implement scan()")
    
    def _check_credentials(self) -> bool:
        """Verify AWS credentials are configured and valid.
        
        Returns:
            bool: True if credentials are valid, False otherwise
        """
        try:
            sts = self.session.client('sts')
            sts.get_caller_identity()
            return True
        except (ClientError, BotoCoreError) as e:
            console.print(f"[red]AWS credentials error: {str(e)}[/]")
            return False
    
    def _add_finding(self, **kwargs) -> None:
        """Helper method to add a finding to the results."""
        finding = Finding(**kwargs)
        self.results.add_finding(finding)
    
    def _get_aws_service_client(self, service_name: str):
        """Get a boto3 client for the specified AWS service.
        
        Args:
            service_name: Name of the AWS service
            
        Returns:
            boto3 client for the specified service
        """
        return self.session.client(service_name)
    
    def _get_aws_service_resource(self, service_name: str):
        """Get a boto3 resource for the specified AWS service.
        
        Args:
            service_name: Name of the AWS service
            
        Returns:
            boto3 resource for the specified service
        """
        return self.session.resource(service_name)
    
    def _paginate(self, client, method_name: str, **kwargs):
        """Helper method to handle AWS API pagination.
        
        Args:
            client: boto3 client
            method_name: Name of the paginator method
            **kwargs: Additional arguments to pass to the paginator
            
        Yields:
            AWS API response pages
        """
        paginator = client.get_paginator(method_name)
        for page in paginator.paginate(**kwargs):
            yield page
