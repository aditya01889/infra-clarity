"""Terraform configuration scanner for Infra Clarity."""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import hcl2
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel

from ..core.models import Finding, ScanResult, Severity, ResourceType

console = Console()

class TerraformScanner:
    """Scans Terraform configurations for potential issues."""
    
    LARGE_INSTANCE_TYPES = [
        'm5.4xlarge', 'm5.8xlarge', 'm5.16xlarge',
        'c5.4xlarge', 'c5.9xlarge', 'c5.18xlarge',
        'r5.4xlarge', 'r5.8xlarge', 'r5.16xlarge'
    ]
    
    REQUIRED_TAGS = ['Name', 'Environment', 'Owner']
    
    def __init__(self, path: str, debug: bool = False):
        """Initialize the scanner with the path to scan.
        
        Args:
            path: Path to the Terraform directory or file to scan
            debug: Whether to enable debug output
        """
        self.path = Path(path).resolve()
        self.results = ScanResult()
        self.console = Console()
        self.debug = debug
        
        if self.debug:
            self.console.print("[yellow]Debug mode enabled[/]")
            self.console.print(f"[dim]Scanning path: {self.path}")
            self.console.print(f"[dim]Working directory: {Path.cwd()}")
    
    def scan(self) -> ScanResult:
        """Scan the specified path for Terraform files and analyze them."""
        if self.debug:
            self.console.print("\n[DEBUG] Starting Terraform scan...")
            self.console.print(f"[DEBUG] Path: {self.path}")
            self.console.print(f"[DEBUG] Current working directory: {Path.cwd()}")
            self.console.print(f"[DEBUG] Path exists: {self.path.exists()}")
            
            if self.path.is_dir():
                self.console.print(f"[DEBUG] Path is a directory")
                try:
                    files = list(self.path.rglob("*.tf"))
                    self.console.print(f"[DEBUG] Found {len(files)} .tf files: {[str(f) for f in files]}")
                    
                    # Print contents of each .tf file for debugging
                    for file in files:
                        try:
                            with open(file, 'r', encoding='utf-8') as f:
                                content = f.read()
                                self.console.print(f"\n[DEBUG] Contents of {file}:")
                                self.console.print("-" * 80)
                                self.console.print(content)
                                self.console.print("-" * 80)
                        except Exception as e:
                            self.console.print(f"[DEBUG] Error reading {file}: {e}")
                            
                except Exception as e:
                    self.console.print(f"[DEBUG] Error listing .tf files: {e}")
            elif self.path.is_file():
                self.console.print(f"[DEBUG] Path is a file")
                self.console.print(f"[DEBUG] File extension: {self.path.suffix}")
                if self.path.suffix == '.tf':
                    try:
                        with open(self.path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            self.console.print("\n[DEBUG] File contents:")
                            self.console.print("-" * 80)
                            self.console.print(content)
                            self.console.print("-" * 80)
                    except Exception as e:
                        self.console.print(f"[DEBUG] Error reading file: {e}")
        
        if not self.path.exists():
            error_msg = f"Path not found: {self.path}"
            self.console.print(f"[red]{error_msg}[/]")
            raise FileNotFoundError(error_msg)
        
        if self.debug:
            self.console.print(f"[DEBUG] Looking for .tf files in: {self.path}")
            self.console.print(f"[DEBUG] Using glob pattern: {self.path}/**/*.tf")
        
        try:
            tf_files = list(self.path.rglob('*.tf'))
            if self.debug:
                self.console.print(f"[DEBUG] Found {len(tf_files)} .tf files:")
                for i, f in enumerate(tf_files, 1):
                    self.console.print(f"[DEBUG] {i}. {f.absolute()}")
        except Exception as e:
            self.console.print(f"[red]Error searching for .tf files: {e}")
            if self.debug:
                import traceback
                self.console.print("[DEBUG] Traceback:")
                self.console.print(traceback.format_exc())
            return self.results
        
        if not tf_files:
            msg = f"No Terraform files found in {self.path}"
            self.console.print(f"[yellow]{msg}[/]")
            return self.results
        
        self.console.print(f"\nFound {len(tf_files)} Terraform file(s) to scan")
        
        with Progress() as progress:
            task = progress.add_task("Scanning Terraform files...", total=len(tf_files))
            
            for tf_file in tf_files:
                progress.update(task, description=f"Scanning {tf_file.name}...")
                self._process_terraform_file(tf_file)
                progress.update(task, advance=1)
        
        # Update metadata
        self.results.metadata.update({
            'scanned_files': len(tf_files),
            'scan_time': str(datetime.now())
        })
        
        # Print final findings
        if not self.results.findings:
            console.print("\n[green]✅ No issues found![/]")
        else:
            console.print(f"\n[bold]Found {len(self.results.findings)} issue(s):[/]")
            for i, finding in enumerate(self.results.findings, 1):
                console.print(f"  {i}. [yellow]{finding.message}[/]")
                if finding.remediation:
                    console.print(f"     [dim]{finding.remediation}[/]")
        
        return self.results
    
    def _process_terraform_file(self, file_path: Path) -> None:
        """Process a single Terraform file."""
        try:
            console = Console()
            
            if self.debug:
                self.console.print("\n" + "=" * 80)
                self.console.print(f"[DEBUG] _process_terraform_file: Starting to process file")
                self.console.print("=" * 80)
                self.console.print(f"[DEBUG] File path: {file_path}")
                self.console.print(f"[DEBUG] Absolute path: {file_path.absolute()}")
                self.console.print(f"[DEBUG] File exists: {file_path.exists()}")
                if file_path.exists():
                    try:
                        file_stat = file_path.stat()
                        self.console.print(f"[DEBUG] File size: {file_stat.st_size} bytes")
                        self.console.print(f"[DEBUG] File permissions: {oct(file_stat.st_mode)[-3:]}")
                        self.console.print(f"[DEBUG] File modified time: {datetime.fromtimestamp(file_stat.st_mtime)}")
                    except Exception as e:
                        self.console.print(f"[ERROR] Could not get file stats: {e}")
                else:
                    self.console.print("[ERROR] File does not exist!")
                    return
                
                self.console.print(f"[DEBUG] Current working directory: {Path.cwd()}")
                self.console.print(f"[DEBUG] Current process ID: {os.getpid()}")
                self.console.print(f"[DEBUG] Current user: {os.getlogin() if hasattr(os, 'getlogin') else 'N/A'}")
                
                # Try to list the directory contents
                try:
                    dir_path = file_path.parent
                    self.console.print(f"[DEBUG] Directory contents of {dir_path}:")
                    for f in dir_path.iterdir():
                        self.console.print(f"  - {f.name} (file: {f.is_file()}, dir: {f.is_dir()})")
                except Exception as e:
                    self.console.print(f"[ERROR] Could not list directory contents: {e}")
            
            console.print(f"\n[bold]Processing file: {file_path}[/]")
            
            # Print the file content for debugging
            if self.debug:
                self.console.print("\n[DEBUG] Attempting to read file content...")
                self.console.print("-" * 80)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    if self.debug:
                        self.console.print("\n[DEBUG] Successfully read file content")
                        self.console.print(f"[DEBUG] Content length: {len(content)} bytes")
                        self.console.print("\n[DEBUG] First 200 chars of file:")
                        self.console.print("-" * 80)
                        self.console.print(content[:200] + ("..." if len(content) > 200 else ""))
                        self.console.print("-" * 80)
                        
                        # Check if content looks like valid HCL
                        if not content.strip():
                            self.console.print("[WARNING] File is empty")
                        elif not any(c in content for c in '{}'):
                            self.console.print("[WARNING] File doesn't contain HCL-like content (missing { or })")
                    
                    # Parse the Terraform file
                    try:
                        parsed = hcl2.loads(content)
                        if self.debug:
                            self.console.print("\n[DEBUG] Successfully parsed HCL2 content")
                            self.console.print(f"[DEBUG] Parsed content type: {type(parsed)}")
                            self.console.print(f"[DEBUG] Parsed content: {parsed}")
                    except Exception as e:
                        self.console.print(f"[red]Error parsing HCL2 content: {e}")
                        if self.debug:
                            import traceback
                            self.console.print("[DEBUG] Traceback:")
                            self.console.print(traceback.format_exc())
                        return
                    
                    if not parsed:
                        self.console.print("[yellow]No content found in the file.[/]")
                        return
                    
                    if self.debug:
                        self.console.print("\n[DEBUG] Parsed content structure:")
                        if isinstance(parsed, dict):
                            self.console.print(f"Top-level keys: {list(parsed.keys())}")
                            if 'resource' in parsed:
                                self.console.print(f"Found {len(parsed['resource'])} resource blocks")
                            if 'module' in parsed:
                                self.console.print(f"Found {len(parsed['module'])} module blocks")
                        else:
                            self.console.print(f"[DEBUG] Parsed content is not a dictionary: {type(parsed)}")
                    
                    # Process resources if present
                    if 'resource' in parsed:
                        if self.debug:
                            self.console.print("\n[DEBUG] Processing resources...")
                        
                        resources = parsed['resource']
                        if not isinstance(resources, list):
                            console.print("[yellow]Warning: resources is not a list, skipping resource checks")
                            return
                            
                        for i, resource_block in enumerate(resources, 1):
                            if not isinstance(resource_block, dict):
                                console.print(f"[yellow]Skipping non-dict resource block {i}: {resource_block}")
                                continue
                                
                            if self.debug:
                                console.print(f"\n[DEBUG] Processing resource block {i}:")
                            
                            # Each block should have a single key (the resource type)
                            for resource_type, resource_items in resource_block.items():
                                if not isinstance(resource_items, dict):
                                    console.print(f"[yellow]Skipping non-dict resource items for {resource_type}: {resource_items}")
                                    continue
                                    
                                if self.debug:
                                    console.print(f"  [dim]Resource type: {resource_type}")
                                
                                # Each resource item is a dict of resource_name -> resource_config
                                for resource_name, resource_config in resource_items.items():
                                    resource_id = f"{resource_type}.{resource_name}"
                                    if self.debug:
                                        console.print(f"  [dim]Processing resource: {resource_id}")
                                    
                                    # Debug: Print resource config
                                    if isinstance(resource_config, dict):
                                        if self.debug:
                                            console.print("  [dim]Resource config:")
                                            console.print(f"  {json.dumps(resource_config, indent=2, ensure_ascii=False)}")
                                        
                                        # Check for instance size issues
                                        if 'aws_instance' in resource_type:
                                            self._check_instance_size(resource_type, resource_config, resource_id, str(file_path))
                                        
                                        # Check for missing tags
                                        self._check_tags(resource_config, resource_id, str(file_path))
                                        
                                        # Check security group rules
                                        if 'aws_security_group' in resource_type:
                                            self._check_security_groups(resource_config, resource_id, str(file_path))
                                    else:
                                        console.print(f"  [yellow]Skipping non-dict resource config: {resource_config}")
                    
                    # Check for modules
                    if 'module' in parsed:
                        if self.debug:
                            self.console.print("\n[DEBUG] Checking modules...")
                        self._check_modules(parsed['module'], str(file_path))
                    
                    # Print the current findings for this file
                    if self.results.findings:
                        console.print("\n[bold]Findings for this file:")
                        for finding in self.results.findings:
                            console.print(f"  - {finding.message}")
                    else:
                        console.print("\n[green]No issues found in this file.[/]")
                        
            except Exception as e:
                console.print(f"[red]Error processing {file_path}: {str(e)}")
                if self.debug:
                    import traceback
                    traceback.print_exc()
                return
                
        except Exception as e:
            console.print(f"[red]Unexpected error processing {file_path}: {str(e)}[/]")
            if self.debug:
                import traceback
                traceback.print_exc()
    
    def _analyze_tf_file(self, file_path: Path) -> None:
        """Analyze a single Terraform file for potential issues."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if not content.strip():
                    console.print(f"[yellow]Empty file: {file_path}[/]")
                    return  # Skip empty files
                
                console.print(f"[blue]Parsing file: {file_path}[/]")
                
                # Debug: Print the first 200 chars of content
                console.print(f"[dim]Content preview: {content[:200]}...[/]")
                
                tf_config = hcl2.loads(content)
                
                # Debug: Print the parsed config
                import json
                console.print(f"[dim]Parsed config: {json.dumps(tf_config, indent=2, default=str)}[/]")
                
                # Ensure we have a dictionary
                if not isinstance(tf_config, dict):
                    console.print(f"[yellow]Unexpected config format in {file_path}: {type(tf_config)}[/]")
                    return
                
                # Check for resources
                resources = tf_config.get('resource', {})
                console.print(f"[dim]Found resources: {resources}")
                
                if isinstance(resources, list):
                    console.print("[yellow]Warning: resources is a list, expected a dictionary[/]")
                    resources = {}
                
                self._check_resources(resources, str(file_path))
                
                # Check for modules
                modules = tf_config.get('module', {})
                if isinstance(modules, list):
                    modules = {}
                self._check_modules(modules, str(file_path))
                
        except Exception as e:
            import traceback
            console.print(f"[red]Error parsing {file_path}: {str(e)}[/]")
            console.print(f"[red]{traceback.format_exc()}[/]")
    
    def _check_resources(self, resources, file_path: str) -> None:
        """Check resources for potential issues.
        
        Args:
            resources: List of resource blocks from HCL2 parser
            file_path: Path to the file being analyzed
        """
        if not resources:
            return
            
        # The HCL2 parser returns a list of resource blocks
        if not isinstance(resources, list):
            return
            
        for resource_block in resources:
            if not isinstance(resource_block, dict):
                continue
                
            # Each resource block is a dict with a single key (the resource type)
            for resource_type, resource_items in resource_block.items():
                if not isinstance(resource_items, dict):
                    continue
                    
                # Each resource item is a dict of resource_name -> resource_config
                for resource_name, resource_config in resource_items.items():
                    resource_id = f"{resource_type}.{resource_name}"
                    
                    # Check for instance size issues
                    if 'aws_instance' in resource_type:
                        self._check_instance_size(resource_type, resource_config, resource_id, file_path)
                    
                    # Check for missing tags
                    self._check_tags(resource_config, resource_id, file_path)
                    
                    # Check security group rules
                    if 'aws_security_group' in resource_type:
                        self._check_security_groups(resource_config, resource_id, file_path)
    
    def _process_resource_blocks(self, resource_type: str, resource_blocks: Dict, file_path: str) -> None:
        """Process a dictionary of resource blocks for a specific resource type."""
        console.print(f"[dim]Processing resource type: {resource_type}")
        
        if not isinstance(resource_blocks, dict):
            console.print(f"[yellow]Skipping non-dict resource_blocks: {type(resource_blocks)}")
            return
            
        for resource_name, resource_config in resource_blocks.items():
            resource_id = f"{resource_type}.{resource_name}"
            console.print(f"[dim]Processing resource: {resource_id}")
            
            # Debug the resource config
            import json
            console.print(f"[dim]Resource config: {json.dumps(resource_config, indent=2, default=str)}")
            
            # Check for instance size issues
            if 'aws_instance' in resource_type:
                console.print("[blue]Checking instance size...")
                self._check_instance_size(resource_type, resource_config, resource_id, file_path)
            
            # Check for missing tags
            if 'tags' in resource_config:
                console.print("[blue]Checking tags...")
                self._check_tags(resource_config, resource_id, file_path)
            
            # Check security group rules
            if 'aws_security_group' in resource_type:
                console.print("[blue]Checking security group rules...")
                self._check_security_groups(resource_config, resource_id, file_path)
    
    def _check_modules(self, modules: Dict, file_path: str) -> None:
        """Check module calls for potential issues."""
        for module_name, module_config in modules.items():
            self._check_tags(module_config, f"module.{module_name}", file_path)
    
    def _check_instance_size(self, resource_type: str, resource_config: Dict, resource_id: str, file_path: str) -> None:
        """Check if an EC2 instance is overprovisioned."""
        console.print(f"\n[bold]Checking instance size for {resource_id}[/]")
        
        if not isinstance(resource_config, dict):
            console.print(f"[yellow]Skipping non-dict resource config: {resource_config}")
            return
            
        # Debug: Print the entire resource config
        import json
        console.print("[dim]Resource config:")
        console.print(json.dumps(resource_config, indent=2))
        
        # Handle both string and list instance_type definitions
        instance_type = None
        if 'instance_type' in resource_config:
            instance_type = resource_config['instance_type']
            console.print(f"[dim]Found instance_type: {instance_type} (type: {type(instance_type)})")
            
            # If it's a list, get the first element (common in Terraform)
            if isinstance(instance_type, list) and instance_type:
                instance_type = instance_type[0]
        else:
            console.print("[yellow]No instance_type found in resource config")
            return
        
        if not instance_type or not isinstance(instance_type, str):
            console.print(f"[yellow]Invalid instance_type: {instance_type} (type: {type(instance_type)})")
            return
            
        console.print(f"[dim]Checking if instance type '{instance_type}' is overprovisioned...")
        
        # Check for overprovisioned instances
        large_instance_sizes = ['xlarge', '2xlarge', '4xlarge', '8xlarge', '16xlarge']
        if any(size in instance_type.lower() for size in large_instance_sizes):
            console.print(f"[green]Found overprovisioned instance: {instance_type}")
            
            # Create a finding for the overprovisioned instance
            finding = Finding(
                resource_id=resource_id,
                resource_type=ResourceType.EC2,  # Assuming EC2 for aws_instance
                finding_type="OVERPROVISIONED_INSTANCE",
                severity=Severity.MEDIUM,
                message=f"Instance {resource_id} may be overprovisioned with type {instance_type}",
                details={
                    'instance_type': instance_type,
                    'file_path': file_path,
                    'resource_type': resource_type
                },
                remediation=(
                    f"Consider using a smaller instance type or implementing auto-scaling. "
                    f"Current instance type: {instance_type}"
                )
            )
            
            # Add the finding to the results
            self.results.add_finding(finding)
            console.print(f"[green]Added finding for overprovisioned instance: {instance_type}")
        else:
            console.print(f"[dim]Instance type {instance_type} is not considered overprovisioned")
    
    def _check_tags(self, config: Dict, resource_id: str, file_path: str) -> None:
        """Check if the resource has required tags."""
        if not isinstance(config, dict):
            return
            
        # Get the tags from the configuration
        tags = {}
        if 'tags' in config and isinstance(config['tags'], dict):
            tags = config['tags']
        
        # Check for required tags
        required_tags = ['Name', 'Environment', 'Owner']
        missing_tags = [tag for tag in required_tags if tag not in tags]
        
        if missing_tags:
            # Determine resource type from resource_id
            resource_type = ResourceType.UNKNOWN
            if 'aws_instance' in resource_id:
                resource_type = ResourceType.EC2
            elif 'aws_security_group' in resource_id:
                resource_type = ResourceType.SECURITY_GROUP
                
            self.results.add_finding(Finding(
                resource_id=resource_id,
                resource_type=resource_type,
                finding_type="MISSING_TAGS",
                severity=Severity.LOW,
                message=f"Resource {resource_id} is missing required tags: {', '.join(missing_tags)}",
                details={
                    'file_path': file_path,
                    'existing_tags': tags,
                    'missing_tags': missing_tags
                },
                remediation=f"Add the following tags to the resource: {', '.join(missing_tags)}"
            ))
    
    def _check_security_groups(self, resource_config: Dict, resource_id: str, file_path: str) -> None:
        """Check for overly permissive security group rules."""
        if not isinstance(resource_config, dict):
            return
            
        if self.debug:
            self.console.print(f"[DEBUG] Checking security group rules for {resource_id}")
            self.console.print(f"[DEBUG] Security group config: {json.dumps(resource_config, indent=2, ensure_ascii=False)}")
        
        # Check for overly permissive ingress rules
        ingress = resource_config.get('ingress', [])
        if not isinstance(ingress, list):
            ingress = [ingress]
            
        for i, rule in enumerate(ingress):
            if not isinstance(rule, dict):
                if self.debug:
                    self.console.print(f"[DEBUG] Skipping non-dict ingress rule: {rule}")
                continue
                
            if self.debug:
                self.console.print(f"[DEBUG] Checking ingress rule {i}: {rule}")
                
            # Check for open CIDR blocks
            cidr_blocks = rule.get('cidr_blocks', [])
            if not isinstance(cidr_blocks, list):
                cidr_blocks = [cidr_blocks]
                
            if self.debug:
                self.console.print(f"[DEBUG] CIDR blocks: {cidr_blocks}")
                
            if '0.0.0.0/0' in cidr_blocks:
                finding = Finding(
                    resource_id=resource_id,
                    resource_type=ResourceType.SECURITY_GROUP,
                    finding_type="OVERLY_PERMISSIVE_INGRESS",
                    severity=Severity.HIGH,
                    message=(
                        f"Security group {resource_id} has an overly permissive ingress rule "
                        f"allowing traffic from 0.0.0.0/0"
                    ),
                    details={
                        'file_path': file_path,
                        'rule_index': i,
                        'cidr_blocks': cidr_blocks,
                        'from_port': rule.get('from_port'),
                        'to_port': rule.get('to_port'),
                        'protocol': rule.get('protocol')
                    },
                    remediation=(
                        "Restrict the source IP range to the minimum required. "
                        "Avoid using 0.0.0.0/0 unless absolutely necessary."
                    )
                )
                if self.debug:
                    self.console.print(f"[DEBUG] Adding finding: {finding}")
                self.results.add_finding(finding)
        
        # Check for overly permissive egress rules
        egress = resource_config.get('egress', [])
        if not isinstance(egress, list):
            egress = [egress]
            
        for i, rule in enumerate(egress):
            if not isinstance(rule, dict):
                if self.debug:
                    self.console.print(f"[DEBUG] Skipping non-dict egress rule: {rule}")
                continue
                
            if self.debug:
                self.console.print(f"[DEBUG] Checking egress rule {i}: {rule}")
                
            # Check for open CIDR blocks
            cidr_blocks = rule.get('cidr_blocks', [])
            if not isinstance(cidr_blocks, list):
                cidr_blocks = [cidr_blocks]
                
            if self.debug:
                self.console.print(f"[DEBUG] CIDR blocks: {cidr_blocks}")
                
            if '0.0.0.0/0' in cidr_blocks:
                finding = Finding(
                    resource_id=resource_id,
                    resource_type=ResourceType.SECURITY_GROUP,
                    finding_type="OVERLY_PERMISSIVE_EGRESS",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Security group {resource_id} has an overly permissive egress rule "
                        f"allowing traffic to 0.0.0.0/0"
                    ),
                    details={
                        'file_path': file_path,
                        'rule_index': i,
                        'cidr_blocks': cidr_blocks,
                        'from_port': rule.get('from_port'),
                        'to_port': rule.get('to_port'),
                        'protocol': rule.get('protocol')
                    },
                    remediation=(
                        "Restrict the destination IP range to the minimum required. "
                        "Avoid using 0.0.0.0/0 unless absolutely necessary."
                    )
                )
                if self.debug:
                    self.console.print(f"[DEBUG] Adding finding: {finding}")
                self.results.add_finding(finding)


def scan_terraform(path: str) -> ScanResult:
    """
    Scan Terraform configurations at the given path.
    
    Args:
        path: Path to the directory containing Terraform files
        
    Returns:
        ScanResult containing any findings
    """
    scanner = TerraformScanner(path)
    return scanner.scan()
