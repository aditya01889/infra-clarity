"""EC2 instance scanner for AWS."""
from typing import Dict, List, Any
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, BotoCoreError

from .base_scanner import AWSScanner
from ...core.models import Finding, Severity, ResourceType

class EC2Scanner(AWSScanner):
    """Scanner for EC2 instances and related resources."""
    
    def scan(self) -> List[Finding]:
        """Scan EC2 instances and related resources for potential issues."""
        if not self._check_credentials():
            return self.results
        
        self._scan_instances()
        self._scan_security_groups()
        self._scan_volumes()
        
        return self.results
    
    def _scan_instances(self) -> None:
        """Scan EC2 instances for potential issues."""
        ec2 = self._get_aws_service_client('ec2')
        
        try:
            for page in self._paginate(ec2, 'describe_instances'):
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        self._check_instance(instance)
        except (ClientError, BotoCoreError) as e:
            self._add_finding(
                resource_id=f"ec2-instance-scan",
                resource_type=ResourceType.EC2,
                finding_type="EC2ScanError",
                severity=Severity.MEDIUM,
                message=f"Error scanning EC2 instances: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_instance(self, instance: Dict[str, Any]) -> None:
        """Check a single EC2 instance for potential issues."""
        instance_id = instance['InstanceId']
        state = instance['State']['Name']
        
        # Check for stopped instances
        if state == 'stopped':
            launch_time = instance.get('LaunchTime')
            if launch_time and (datetime.now(launch_time.tzinfo) - launch_time) > timedelta(days=30):
                self._add_finding(
                    resource_id=instance_id,
                    resource_type=ResourceType.EC2,
                    finding_type="StoppedInstance",
                    severity=Severity.LOW,
                    message=f"EC2 instance {instance_id} has been stopped for more than 30 days",
                    details={
                        'launch_time': str(launch_time),
                        'instance_type': instance.get('InstanceType'),
                        'tags': {t['Key']: t['Value'] for t in instance.get('Tags', [])}
                    },
                    remediation="Consider terminating the instance if it's no longer needed"
                )
        
        # Check for untagged instances
        tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
        required_tags = ['Name', 'Environment', 'Owner']
        missing_tags = [tag for tag in required_tags if tag not in tags]
        
        if missing_tags:
            self._add_finding(
                resource_id=instance_id,
                resource_type=ResourceType.EC2,
                finding_type="MissingTags",
                severity=Severity.MEDIUM,
                message=f"EC2 instance {instance_id} is missing required tags",
                details={
                    'missing_tags': missing_tags,
                    'existing_tags': tags
                },
                remediation=f"Add the following tags: {', '.join(missing_tags)}"
            )
    
    def _scan_security_groups(self) -> None:
        """Scan security groups for overly permissive rules."""
        ec2 = self._get_aws_service_client('ec2')
        
        try:
            for page in self._paginate(ec2, 'describe_security_groups'):
                for sg in page.get('SecurityGroups', []):
                    self._check_security_group(sg)
        except (ClientError, BotoCoreError) as e:
            self._add_finding(
                resource_id=f"sg-scan",
                resource_type=ResourceType.SECURITY_GROUP,
                finding_type="SecurityGroupScanError",
                severity=Severity.MEDIUM,
                message=f"Error scanning security groups: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_security_group(self, sg: Dict[str, Any]) -> None:
        """Check a single security group for potential issues."""
        sg_id = sg['GroupId']
        
        for perm in sg.get('IpPermissions', []):
            for ip_range in perm.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    self._add_finding(
                        resource_id=sg_id,
                        resource_type=ResourceType.SECURITY_GROUP,
                        finding_type="OverlyPermissiveRule",
                        severity=Severity.HIGH,
                        message=f"Security group {sg_id} allows traffic from anywhere (0.0.0.0/0)",
                        details={
                            'port_range': f"{perm.get('FromPort', 'any')}-{perm.get('ToPort', 'any')}",
                            'protocol': perm.get('IpProtocol', 'all'),
                            'description': ip_range.get('Description', 'No description')
                        },
                        remediation="Restrict the IP range to only necessary sources"
                    )
    
    def _scan_volumes(self) -> None:
        """Scan EBS volumes for potential issues."""
        ec2 = self._get_aws_service_client('ec2')
        
        try:
            for page in self._paginate(ec2, 'describe_volumes'):
                for volume in page.get('Volumes', []):
                    self._check_volume(volume)
        except (ClientError, BotoCoreError) as e:
            self._add_finding(
                resource_id=f"volume-scan",
                resource_type=ResourceType.EBS,
                finding_type="VolumeScanError",
                severity=Severity.MEDIUM,
                message=f"Error scanning EBS volumes: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_volume(self, volume: Dict[str, Any]) -> None:
        """Check a single EBS volume for potential issues."""
        volume_id = volume['VolumeId']
        
        # Check for unattached volumes
        if not volume.get('Attachments'):
            create_time = volume.get('CreateTime')
            if create_time and (datetime.now(create_time.tzinfo) - create_time) > timedelta(days=30):
                self._add_finding(
                    resource_id=volume_id,
                    resource_type=ResourceType.EBS,
                    finding_type="UnattachedVolume",
                    severity=Severity.MEDIUM,
                    message=f"EBS volume {volume_id} has been unattached for more than 30 days",
                    details={
                        'size_gb': volume.get('Size'),
                        'volume_type': volume.get('VolumeType'),
                        'create_time': str(create_time)
                    },
                    remediation="Consider deleting the volume if it's no longer needed"
                )
        
        # Check for unencrypted volumes
        if not volume.get('Encrypted', False):
            self._add_finding(
                resource_id=volume_id,
                resource_type=ResourceType.EBS,
                finding_type="UnencryptedVolume",
                severity=Severity.HIGH,
                message=f"EBS volume {volume_id} is not encrypted",
                details={
                    'size_gb': volume.get('Size'),
                    'volume_type': volume.get('VolumeType'),
                    'state': volume.get('State')
                },
                remediation="Enable encryption for the EBS volume"
            )
