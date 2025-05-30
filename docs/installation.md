# Installation

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git (for development)

## Installation Methods

### Using pip (Recommended)

```bash
pip install infra-clarity
```

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/infra-clarity.git
   cd infra-clarity
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   # On Windows
   python -m venv venv
   .\venv\Scripts\activate
   
   # On macOS/Linux
   python -m venv venv
   source venv/bin/activate
   ```

3. Install the package in development mode:
   ```bash
   pip install -e .
   ```

### Verifying the Installation

```bash
infra-clarity --version
```

## Upgrading

```bash
pip install --upgrade infra-clarity
```

## Uninstalling

```bash
pip uninstall infra-clarity
```
