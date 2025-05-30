# Usage Guide

## Basic Commands

### Scan Terraform Configurations

```bash
# Basic usage
infra-clarity scan-terraform /path/to/terraform/directory

# Enable debug output
infra-clarity scan-terraform --debug /path/to/terraform/directory

# Save results to a JSON file
infra-clarity scan-terraform --output results.json /path/to/terraform/directory
```

### Scan AWS Account (Coming Soon)

```bash
# Using default profile and region
infra-clarity scan-aws

# Specify AWS profile and region
infra-clarity scan-aws --profile myprofile --region us-west-2
```

## Command Line Options

### Global Options

- `--version`: Show the version and exit
- `--help`: Show help message and exit

### scan-terraform Command

```
Usage: infra-clarity scan-terraform [OPTIONS] PATH

  Scan Terraform configurations for potential issues.

Options:
  --debug / --no-debug    Enable debug output  [default: no-debug]
  --output FILENAME       Save results to a JSON file
  --format [text|json]    Output format  [default: text]
  --help                  Show this message and exit.
```

## Example Output

### Text Output

```
🔍 Scanning Terraform files...

📁 Found 3 Terraform files to scan

✅ Scan completed

🔍 Found 2 potential issues:

1. [HIGH] Overprovisioned EC2 instance detected
   - Resource: aws_instance.web_server
   - Issue: Instance type 't3.xlarge' may be overprovisioned
   - Suggestion: Consider downgrading to 't3.medium' for estimated 60% cost savings

2. [MEDIUM] Overly permissive security group rule
   - Resource: aws_security_group.default
   - Issue: Ingress rule allows all traffic (0.0.0.0/0)
   - Suggestion: Restrict to specific IP ranges or security groups
```

### JSON Output

```json
{
  "findings": [
    {
      "resource_type": "aws_instance",
      "resource_name": "web_server",
      "severity": "HIGH",
      "message": "Overprovisioned EC2 instance detected",
      "details": "Instance type 't3.xlarge' may be overprovisioned",
      "suggestion": "Consider downgrading to 't3.medium' for estimated 60% cost savings"
    },
    {
      "resource_type": "aws_security_group",
      "resource_name": "default",
      "severity": "MEDIUM",
      "message": "Overly permissive security group rule",
      "details": "Ingress rule allows all traffic (0.0.0.0/0)",
      "suggestion": "Restrict to specific IP ranges or security groups"
    }
  ],
  "summary": {
    "total_findings": 2,
    "high_severity": 1,
    "medium_severity": 1,
    "low_severity": 0
  }
}
```
