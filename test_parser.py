"""Test script to verify HCL2 parsing."""
import os
import sys
import json
import hcl2
from pathlib import Path

def print_section(title, char='-'):
    """Print a section header."""
    print(f"\n{title}")
    print(char * 80)

def main():
    """Main function to test HCL2 parsing."""
    # Path to the test Terraform file
    test_file = Path("examples/terraform/main.tf").resolve()
    
    if not test_file.exists():
        print(f"Error: Test file not found at {test_file}")
        return 1
    
    print_section(f"Reading file: {test_file}")
    try:
        with open(test_file, 'r', encoding='utf-8') as f:
            content = f.read()
        print(f"Successfully read {len(content)} characters")
    except Exception as e:
        print(f"Error reading file: {e}")
        return 1
    
    print_section("File content:")
    print(content)
    
    try:
        print_section("Parsing HCL2...")
        parsed = hcl2.loads(content)
        
        print_section("Parsed output (raw):")
        print(json.dumps(parsed, indent=2, default=str))
        
        # Extract resources
        resources = parsed.get('resource', [])
        print_section(f"Found {len(resources)} resource blocks")
        
        if not resources:
            print("No resources found in the file.")
            return 0
            
        for i, resource_block in enumerate(resources, 1):
            if not isinstance(resource_block, dict):
                print(f"\nResource block {i} is not a dictionary: {resource_block}")
                continue
                
            print(f"\nResource block {i}:")
            
            for resource_type, resource_items in resource_block.items():
                if not isinstance(resource_items, dict):
                    print(f"  Type: {resource_type} (skipping, not a dictionary)")
                    continue
                    
                print(f"  Type: {resource_type}")
                
                for name, config in resource_items.items():
                    print(f"  Name: {name}")
                    print(f"  Config type: {type(config).__name__}")
                    
                    # Print config with indentation for better readability
                    if isinstance(config, dict):
                        for k, v in config.items():
                            print(f"    {k}: {v}")
                    else:
                        print(f"    {config}")
                    
                    # Check for instance type if this is an EC2 instance
                    if resource_type == 'aws_instance':
                        instance_type = config.get('instance_type') if isinstance(config, dict) else None
                        print(f"  Instance type: {instance_type}")
                        
                        if instance_type and 'xlarge' in str(instance_type):
                            print("  [WARNING] Possible overprovisioned instance!")
                    
                    # Check for security group rules
                    if resource_type == 'aws_security_group' and isinstance(config, dict):
                        ingress_rules = config.get('ingress', [])
                        if isinstance(ingress_rules, list):
                            for rule in ingress_rules:
                                if isinstance(rule, dict) and rule.get('cidr_blocks') == ['0.0.0.0/0']:
                                    print("  [WARNING] Publicly accessible security group rule!")
        
        return 0
        
    except Exception as e:
        print_section("Error parsing HCL2", '!')
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
