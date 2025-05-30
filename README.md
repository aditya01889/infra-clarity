# Infra Clarity

[![PyPI Version](https://img.shields.io/pypi/v/infra-clarity)](https://pypi.org/project/infra-clarity/)
[![Python Version](https://img.shields.io/pypi/pyversions/infra-clarity)](https://pypi.org/project/infra-clarity/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Tests](https://github.com/aditya01889/infra-clarity/actions/workflows/ci.yml/badge.svg)](https://github.com/aditya01889/infra-clarity/actions/workflows/ci.yml)
[![Documentation Status](https://github.com/aditya01889/infra-clarity/actions/workflows/gh-pages.yml/badge.svg)](https://aditya01889.github.io/infra-clarity/)

> **Note**: This project is currently in active development. Some features may not be fully implemented yet.

Infra Clarity is a powerful CLI tool designed to help developers and DevOps engineers identify cloud misconfigurations and unnecessary expenses in their infrastructure code. Currently focusing on AWS and Terraform, it helps you maintain secure and cost-effective cloud infrastructure.

## 🌟 Features

- **Terraform Analysis**: Scan `.tf` files for potential issues and misconfigurations
- **Security Checks**: Identify overly permissive security group rules and IAM policies
- **Cost Optimization**: Detect overprovisioned resources that could be costing you money
- **AWS Resource Scanning**: Identify security risks and cost optimizations in your AWS account
- **Rich CLI Output**: Color-coded results with severity levels and remediation suggestions
- **Modular Architecture**: Easy to extend with new scanners and cloud providers

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git (for development)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/infra-clarity.git
   cd infra-clarity
   ```

2. (Recommended) Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```

3. Install the package in development mode:
   ```bash
   pip install -e .
   ```

4. Install development dependencies (optional):
   ```bash
   pip install -r requirements-dev.txt
   ```

## 🛠 Usage

### Scan Terraform Configurations

```bash
# Basic usage
infra-clarity scan-terraform /path/to/terraform/directory

# Enable debug output
infra-clarity scan-terraform --debug /path/to/terraform/directory

# Save results to a JSON file
infra-clarity scan-terraform --output results.json /path/to/terraform/directory
```

### Example Output

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

### Scan AWS Account (Coming Soon)

```bash
# Using default profile and region
infra-clarity scan-aws

# Specify AWS profile and region
infra-clarity scan-aws --profile myprofile --region us-west-2
```

## 🧪 Development

### Project Structure

```
infra-clarity/
├── infra_clarity/
│   ├── __init__.py
│   ├── cli.py                  # CLI interface using Typer
│   ├── core/
│   │   ├── __init__.py
│   │   ├── models.py          # Data models and enums
│   │   └── utils.py           # Utility functions
│   └── scanners/
│       ├── __init__.py
│       ├── base_scanner.py    # Base scanner class
│       ├── terraform_scanner.py
│       └── aws/               # AWS-specific scanners (coming soon)
│           ├── __init__.py
│           ├── base_scanner.py
│           ├── ec2_scanner.py
│           └── s3_scanner.py
├── examples/                   # Example configurations
│   └── terraform/
│       └── main.tf
├── tests/                      # Unit and integration tests
├── .github/                   # GitHub workflows
│   └── workflows/
│       └── tests.yml
├── .gitignore
├── pyproject.toml             # Project metadata and dependencies
├── README.md
└── requirements-dev.txt       # Development dependencies
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage report
pytest --cov=infra_clarity tests/

# Run a specific test file
pytest tests/test_terraform_scanner.py -v
```

### Adding a New Scanner

1. Create a new Python file in the appropriate scanner directory
2. Create a class that inherits from the relevant base scanner
3. Implement the required methods (typically `scan()`)
4. Register the scanner in the appropriate `__init__.py`
5. Add unit tests in the `tests/` directory

### Code Style

This project uses:
- Black for code formatting
- isort for import sorting
- flake8 for linting

Run the following before committing:
```bash
black .
isort .
flake8
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ✨ Demo

[![Demo Video](https://img.youtube.com/vi/YOUR_VIDEO_ID/0.jpg)](https://www.youtube.com/watch?v=YOUR_VIDEO_ID)

## 📬 Contact

Your Name - [@yourtwitter](https://twitter.com/yourtwitter) - your.email@example.com

Project Link: [https://github.com/yourusername/infra-clarity](https://github.com/yourusername/infra-clarity)

## 🙏 Acknowledgments

- [Python](https://www.python.org/)
- [Typer](https://typer.tiangolo.com/) for the CLI interface
- [Rich](https://github.com/Textualize/rich) for beautiful terminal output
- [python-hcl2](https://github.com/amplify-education/python-hcl2) for Terraform file parsing
