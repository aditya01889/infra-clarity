# Welcome to Infra Clarity

Infra Clarity is a powerful CLI tool designed to help developers and DevOps engineers identify cloud misconfigurations and unnecessary expenses in their infrastructure code.

## Features

- **Terraform Configuration Analysis**: Scan `.tf` files for potential issues and misconfigurations
- **Security Checks**: Identify overly permissive security group rules and IAM policies
- **Cost Optimization**: Detect overprovisioned resources that could be costing you money
- **AWS Resource Scanning**: Identify security risks and cost optimizations in your AWS account
- **Rich CLI Output**: Color-coded results with severity levels and remediation suggestions

## Quick Start

```bash
# Install the package
pip install infra-clarity

# Scan a Terraform directory
infra-clarity scan-terraform /path/to/terraform/directory
```

## Documentation

- [Installation](installation.md)
- [Usage Guide](usage.md)
- [Development Guide](development.md)

## Contributing

Contributions are welcome! Please read our [Contributing Guide](https://github.com/yourusername/infra-clarity/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.
