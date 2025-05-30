"""Simple test script to verify file reading."""
import os
import sys
from pathlib import Path

def main():
    """Main function to test file reading."""
    # Path to the test file
    test_file = Path("examples/terraform/main.tf").resolve()
    
    print("=" * 80)
    print(f"Testing file reading for: {test_file}")
    print(f"File exists: {test_file.exists()}")
    print(f"File size: {test_file.stat().st_size if test_file.exists() else 0} bytes")
    print(f"Current working directory: {Path.cwd()}")
    
    if not test_file.exists():
        print("\nError: Test file does not exist!")
        print("\nDirectory contents:")
        for f in test_file.parent.iterdir():
            print(f"  - {f.name} (file: {f.is_file()}, dir: {f.is_dir()})")
        return
    
    try:
        print("\nAttempting to read file...")
        with open(test_file, 'r', encoding='utf-8') as f:
            content = f.read()
            print(f"Successfully read {len(content)} bytes")
            print("\nFirst 200 characters:")
            print("-" * 80)
            print(content[:200])
            print("-" * 80)
    except Exception as e:
        print(f"\nError reading file: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
    print("\nTest complete")
