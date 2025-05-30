"""S3 bucket scanner for AWS."""
from typing import Dict, List, Any
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, BotoCoreError

from .base_scanner import AWSScanner
from ...core.models import Finding, Severity, ResourceType

class S3Scanner(AWSScanner):
    """Scanner for S3 buckets and related resources."""
    
    def scan(self) -> List[Finding]:
        """Scan S3 buckets for potential issues."""
        if not self._check_credentials():
            return self.results
        
        self._scan_buckets()
        return self.results
    
    def _scan_buckets(self) -> None:
        """Scan all S3 buckets for potential issues."""
        s3 = self._get_aws_service_client('s3')
        s3_resource = self._get_aws_service_resource('s3')
        
        try:
            response = s3.list_buckets()
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                self._check_bucket_permissions(s3, s3_resource, bucket_name)
                self._check_bucket_encryption(s3, bucket_name)
                self._check_bucket_logging(s3, bucket_name)
                self._check_bucket_versioning(s3, bucket_name)
                
        except (ClientError, BotoCoreError) as e:
            self._add_finding(
                resource_id="s3-bucket-scan",
                resource_type=ResourceType.S3,
                finding_type="S3ScanError",
                severity=Severity.MEDIUM,
                message=f"Error scanning S3 buckets: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_bucket_permissions(self, s3_client, s3_resource, bucket_name: str) -> None:
        """Check S3 bucket permissions for potential issues."""
        try:
            # Check bucket policy
            try:
                policy = s3_resource.BucketPolicy(bucket_name).policy
                if policy:
                    self._analyze_bucket_policy(bucket_name, policy)
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    pass  # No bucket policy is not necessarily an issue
                else:
                    raise
            
            # Check bucket ACL
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            self._analyze_bucket_acl(bucket_name, acl)
            
            # Check public access block configuration
            try:
                public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                self._analyze_public_access_block(bucket_name, public_access_block)
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                    raise
                
        except (ClientError, BotoCoreError) as e:
            self._add_finding(
                resource_id=bucket_name,
                resource_type=ResourceType.S3,
                finding_type="S3PermissionCheckError",
                severity=Severity.MEDIUM,
                message=f"Error checking permissions for S3 bucket {bucket_name}: {str(e)}",
                details={"error": str(e)}
            )
    
    def _analyze_bucket_policy(self, bucket_name: str, policy: Dict) -> None:
        """Analyze S3 bucket policy for potential issues."""
        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow' and statement.get('Principal') == '*':
                self._add_finding(
                    resource_id=bucket_name,
                    resource_type=ResourceType.S3,
                    finding_type="PublicBucketPolicy",
                    severity=Severity.HIGH,
                    message=f"S3 bucket {bucket_name} has a public bucket policy",
                    details={
                        'statement': statement,
                        'action': statement.get('Action', 'Unknown')
                    },
                    remediation="Review and modify the bucket policy to restrict access to specific principals"
                )
    
    def _analyze_bucket_acl(self, bucket_name: str, acl: Dict) -> None:
        """Analyze S3 bucket ACL for potential issues."""
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if 'URI' in grantee and 'AllUsers' in grantee['URI']:
                self._add_finding(
                    resource_id=bucket_name,
                    resource_type=ResourceType.S3,
                    finding_type="PublicBucketACL",
                    severity=Severity.HIGH,
                    message=f"S3 bucket {bucket_name} has a public ACL",
                    details={
                        'permission': grant.get('Permission'),
                        'grantee': grantee['URI']
                    },
                    remediation="Modify the bucket ACL to remove public access"
                )
    
    def _analyze_public_access_block(self, bucket_name: str, config: Dict) -> None:
        """Analyze S3 public access block configuration."""
        config = config.get('PublicAccessBlockConfiguration', {})
        
        if not all([
            config.get('BlockPublicAcls', False),
            config.get('IgnorePublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('RestrictPublicBuckets', False)
        ]):
            self._add_finding(
                resource_id=bucket_name,
                resource_type=ResourceType.S3,
                finding_type="InsecurePublicAccessBlock",
                severity=Severity.MEDIUM,
                message=f"S3 bucket {bucket_name} has insecure public access block settings",
                details={
                    'block_public_acls': config.get('BlockPublicAcls', False),
                    'ignore_public_acls': config.get('IgnorePublicAcls', False),
                    'block_public_policy': config.get('BlockPublicPolicy', False),
                    'restrict_public_buckets': config.get('RestrictPublicBuckets', False)
                },
                remediation="Enable all public access block settings for the bucket"
            )
    
    def _check_bucket_encryption(self, s3_client, bucket_name: str) -> None:
        """Check if S3 bucket has encryption enabled."""
        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                self._add_finding(
                    resource_id=bucket_name,
                    resource_type=ResourceType.S3,
                    finding_type="UnencryptedBucket",
                    severity=Severity.HIGH,
                    message=f"S3 bucket {bucket_name} does not have server-side encryption enabled",
                    remediation="Enable server-side encryption for the bucket"
                )
    
    def _check_bucket_logging(self, s3_client, bucket_name: str) -> None:
        """Check if S3 bucket has logging enabled."""
        try:
            logging = s3_client.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' not in logging:
                self._add_finding(
                    resource_id=bucket_name,
                    resource_type=ResourceType.S3,
                    finding_type="LoggingDisabled",
                    severity=Severity.MEDIUM,
                    message=f"S3 bucket {bucket_name} does not have server access logging enabled",
                    remediation="Enable server access logging for the bucket"
                )
        except ClientError as e:
            self._add_finding(
                resource_id=bucket_name,
                resource_type=ResourceType.S3,
                finding_type="LoggingCheckError",
                severity=Severity.LOW,
                message=f"Error checking logging configuration for S3 bucket {bucket_name}: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_bucket_versioning(self, s3_client, bucket_name: str) -> None:
        """Check if S3 bucket has versioning enabled."""
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                self._add_finding(
                    resource_id=bucket_name,
                    resource_type=ResourceType.S3,
                    finding_type="VersioningDisabled",
                    severity=Severity.MEDIUM,
                    message=f"S3 bucket {bucket_name} does not have versioning enabled",
                    remediation="Enable versioning to protect against accidental deletions and overwrites"
                )
        except ClientError as e:
            self._add_finding(
                resource_id=bucket_name,
                resource_type=ResourceType.S3,
                finding_type="VersioningCheckError",
                severity=Severity.LOW,
                message=f"Error checking versioning configuration for S3 bucket {bucket_name}: {str(e)}",
                details={"error": str(e)}
            )
