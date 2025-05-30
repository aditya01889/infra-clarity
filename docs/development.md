# Development Guide

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Set up the development environment:
   ```bash
   # Create and activate a virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   
   # Install development dependencies
   pip install -e ".[dev]"
   ```

## Project Structure

```
infra-clarity/
├── infra_clarity/           # Main package
│   ├── __init__.py
│   ├── cli.py              # CLI interface using Typer
│   ├── core/               # Core functionality
│   └── scanners/           # Scanner implementations
├── tests/                  # Unit and integration tests
├── docs/                   # Documentation source
└── examples/               # Example configurations
```

## Running Tests

```bash
# Run all tests
pytest

# Run tests with coverage report
pytest --cov=infra_clarity tests/

# Run a specific test file
pytest tests/test_terraform_scanner.py -v
```

## Code Style

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

## Adding a New Scanner

1. Create a new Python file in the appropriate scanner directory
2. Create a class that inherits from the relevant base scanner
3. Implement the required methods (typically `scan()`)
4. Register the scanner in the appropriate `__init__.py`
5. Add unit tests in the `tests/` directory

## Documentation

Documentation is built using [MkDocs](https://www.mkdocs.org/) with the [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) theme.

To serve the documentation locally:

```bash
mkdocs serve
```

To build the documentation:

```bash
mkdocs build
```

## Pull Requests

1. Create a new branch for your feature or bugfix
2. Write tests for your changes
3. Ensure all tests pass
4. Update documentation if needed
5. Submit a pull request to the `main` branch

## Release Process

1. Update the version in `pyproject.toml`
2. Update the changelog
3. Create a new release on GitHub
4. The GitHub Action will automatically publish to PyPI
