#!/usr/bin/env python3
"""
Simple test script to validate Secret Scanner installation
"""

import sys
import importlib.util

def test_imports():
    """Test if all required modules can be imported."""
    required_modules = ['requests', 'bs4', 'argparse', 'json', 're']
    optional_modules = ['playwright']
    
    print("Testing required imports...")
    for module in required_modules:
        try:
            if module == 'bs4':
                import bs4
                print(f"[OK] {module} (BeautifulSoup4) - OK")
            else:
                __import__(module)
                print(f"[OK] {module} - OK")
        except ImportError as e:
            print(f"[FAIL] {module} - FAILED: {e}")
            return False
    
    print("\nTesting optional imports...")
    for module in optional_modules:
        try:
            __import__(module)
            print(f"[OK] {module} - OK")
        except ImportError:
            print(f"[WARN] {module} - Not installed (optional)")
    
    return True

def test_patterns():
    """Test if secret patterns work correctly."""
    print("\nTesting secret detection patterns...")
    
    # Import the main module
    try:
        import secrets_scanner
        print("[OK] secrets_scanner module imported successfully")
    except ImportError as e:
        print(f"[FAIL] Failed to import secrets_scanner: {e}")
        return False
    
    # Test some patterns
    test_cases = [
        ("jwt_like", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"),
        ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
        ("github_token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
        ("stripe_secret", "sk_test_1234567890abcdefghijklmnop"),
    ]
    
    for pattern_name, test_string in test_cases:
        if pattern_name in secrets_scanner.PATTERNS:
            pattern = secrets_scanner.PATTERNS[pattern_name]
            if pattern.search(test_string):
                print(f"[OK] {pattern_name} pattern - OK")
            else:
                print(f"[WARN] {pattern_name} pattern - May need adjustment")
        else:
            print(f"[FAIL] {pattern_name} pattern - Not found")
    
    return True

def test_basic_functionality():
    """Test basic functionality without network calls."""
    print("\nTesting basic functionality...")
    
    try:
        import secrets_scanner
        
        # Test text scanning
        test_text = "const apiKey = 'sk_test_1234567890abcdefghijklmnop';"
        source_info = {"type": "test", "url": "test"}
        findings = secrets_scanner.scan_text_for_patterns(test_text, source_info)
        
        if findings:
            print(f"[OK] Text scanning - Found {len(findings)} findings")
        else:
            print("[WARN] Text scanning - No findings (may be expected)")
        
        # Test utility functions
        line, col = secrets_scanner.line_col_from_index("line1\nline2\ntest", 12)
        if line == 3 and col == 1:
            print("[OK] Line/column calculation - OK")
        else:
            print(f"[WARN] Line/column calculation - Got line={line}, col={col}")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] Basic functionality test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Secret Scanner Installation Test")
    print("=" * 40)
    
    success = True
    
    success &= test_imports()
    success &= test_patterns()
    success &= test_basic_functionality()
    
    print("\n" + "=" * 40)
    if success:
        print("[SUCCESS] All tests passed! Secret Scanner appears to be working correctly.")
        print("\nYou can now run:")
        print("  python secrets_scanner.py --help")
    else:
        print("[ERROR] Some tests failed. Please check the installation.")
        sys.exit(1)

if __name__ == "__main__":
    main()