"""Test script for the Terraform scanner."""
import sys
import os
import traceback
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def print_section(title):
    """Print a section header."""
    print(f"\n{'='*80}")
    print(f" {title}")
    print(f"{'='*80}")

def test_scanner():
    """Test the Terraform scanner with debug output."""
    print_section("Starting Terraform Scanner Test")
    
    try:
        # Import the scanner module
        print("\n[1/4] Importing scanner module...")
        from infra_clarity.scanners.terraform_scanner import TerraformScanner
        print("✅ Successfully imported TerraformScanner")
        
        # Path to the test Terraform files
        test_path = os.path.join("examples", "terraform")
        abs_test_path = os.path.abspath(test_path)
        
        print(f"\n[2/4] Test configuration:")
        print(f"  - Test path: {test_path}")
        print(f"  - Absolute path: {abs_test_path}")
        print(f"  - Current working directory: {os.getcwd()}")
        print(f"  - Path exists: {os.path.exists(abs_test_path)}")
        
        # List files in the test directory
        if os.path.exists(abs_test_path):
            print(f"\n  Files in test directory:")
            for f in os.listdir(abs_test_path):
                full_path = os.path.join(abs_test_path, f)
                print(f"  - {f} (exists: {os.path.exists(full_path)})")
        
        # Initialize the scanner with debug mode
        print("\n[3/4] Initializing scanner...")
        scanner = TerraformScanner(test_path, debug=True)
        print("✅ Scanner initialized successfully")
        
        # Run the scan
        print("\n[4/4] Running scan...")
        results = scanner.scan()
        print("✅ Scan completed")
        
        # Print results
        print_section("Scan Results")
        if not hasattr(results, 'findings'):
            print("❌ No 'findings' attribute in results object")
            print(f"Results object: {results}")
            print(f"Results type: {type(results)}")
            print(f"Results dir: {dir(results)}")
            return
            
        findings = results.findings if hasattr(results, 'findings') else []
        print(f"Found {len(findings)} issues.")
        
        for i, finding in enumerate(findings, 1):
            print(f"\n{i}. {finding.message}")
            print(f"   Severity: {finding.severity}")
            print(f"   Type: {finding.finding_type}")
            if hasattr(finding, 'details'):
                print(f"   Details: {finding.details}")
            print(f"   Remediation: {finding.remediation}")
    
    except Exception as e:
        print_section("ERROR")
        print(f"An error occurred: {e}")
        print("\nTraceback:")
        traceback.print_exc()

if __name__ == "__main__":
    test_scanner()
    print_section("Test Complete")
