"""Minimal test script for the Terraform scanner."""
import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def main():
    """Run a minimal test of the scanner."""
    print("=" * 80)
    print("MINIMAL SCANNER TEST")
    print("=" * 80)
    
    # Import the scanner
    try:
        from infra_clarity.scanners.terraform_scanner import TerraformScanner
        print("✅ Successfully imported TerraformScanner")
    except Exception as e:
        print(f"❌ Failed to import TerraformScanner: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Test file path
    test_file = Path("examples/terraform/main.tf").resolve()
    print(f"\nTest file: {test_file}")
    print(f"File exists: {test_file.exists()}")
    
    if not test_file.exists():
        print("\nError: Test file does not exist!")
        return
    
    # Create scanner instance
    try:
        print("\nCreating scanner instance...")
        scanner = TerraformScanner(str(test_file.parent), debug=True)
        print("✅ Scanner created successfully")
        
        # Run scan
        print("\nRunning scan...")
        results = scanner.scan()
        print(f"✅ Scan completed. Found {len(results.findings)} issues.")
        
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
    print("\nTest complete")
