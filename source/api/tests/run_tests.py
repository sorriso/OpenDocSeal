#!/usr/bin/env python3
"""
Path: infrastructure/source/api/tests/run_tests.py
Version: 1
"""

import sys
import os
import subprocess
import argparse
import time
from pathlib import Path
from typing import List, Dict, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def run_command(cmd: List[str], description: str, cwd: Optional[str] = None) -> tuple[bool, str]:
    """
    Run a command and return success status and output
    
    Args:
        cmd: Command to run as list
        description: Description of the command
        cwd: Working directory
        
    Returns:
        Tuple of (success, output)
    """
    try:
        print(f"🏃 Running {description}...")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            print(f"✅ {description} passed")
            return True, result.stdout
        else:
            print(f"❌ {description} failed")
            print(f"   Error: {result.stderr}")
            return False, result.stderr
            
    except subprocess.TimeoutExpired:
        print(f"⏰ {description} timed out")
        return False, "Command timed out"
    except Exception as e:
        print(f"💥 {description} crashed: {e}")
        return False, str(e)


def check_test_environment() -> bool:
    """Check if test environment is ready"""
    print("🔍 Checking test environment...")
    
    # Check if pytest is available
    try:
        import pytest
        print(f"  ✅ pytest {pytest.__version__} available")
    except ImportError:
        print("  ❌ pytest not available")
        print("     Install with: pip install -r requirements-test.txt")
        return False
    
    # Check if required dependencies are available
    required_packages = [
        "pytest-asyncio",
        "pytest-mock", 
        "pytest-cov",
        "requests-mock"
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"  ❌ Missing test packages: {', '.join(missing_packages)}")
        print("     Install with: pip install -r requirements-test.txt")
        return False
    
    print("  ✅ Test environment ready")
    return True


def run_security_tests(verbose: bool = False) -> bool:
    """Run security-related tests"""
    cmd = ["python", "-m", "pytest", "test_security.py", "-v" if verbose else "-q"]
    success, output = run_command(cmd, "Security tests", cwd="tests")
    
    if verbose and output:
        print(output)
    
    return success


def run_logging_tests(verbose: bool = False) -> bool:
    """Run logging-related tests"""
    cmd = ["python", "-m", "pytest", "test_logging.py", "-v" if verbose else "-q"]
    success, output = run_command(cmd, "Logging tests", cwd="tests")
    
    if verbose and output:
        print(output)
    
    return success


def run_rate_limiting_tests(verbose: bool = False) -> bool:
    """Run rate limiting tests"""
    cmd = ["python", "-m", "pytest", "test_rate_limiting.py", "-v" if verbose else "-q"]
    success, output = run_command(cmd, "Rate limiting tests", cwd="tests")
    
    if verbose and output:
        print(output)
    
    return success


def run_database_tests(verbose: bool = False) -> bool:
    """Run database tests"""
    cmd = ["python", "-m", "pytest", "test_database.py", "-v" if verbose else "-q"]
    success, output = run_command(cmd, "Database tests", cwd="tests")
    
    if verbose and output:
        print(output)
    
    return success


def run_all_tests(verbose: bool = False, coverage: bool = False) -> bool:
    """Run all available tests"""
    cmd = ["python", "-m", "pytest"]
    
    if coverage:
        cmd.extend(["--cov=../", "--cov-report=html", "--cov-report=term-missing"])
    
    if verbose:
        cmd.append("-v")
    else:
        cmd.append("-q")
    
    # Add test files explicitly
    test_files = [
        "test_security.py",
        "test_logging.py", 
        "test_rate_limiting.py",
        "test_database.py"
    ]
    
    # Only add files that exist
    existing_files = [f for f in test_files if Path("tests") / f]
    cmd.extend(existing_files)
    
    success, output = run_command(cmd, "All tests", cwd="tests")
    
    if verbose and output:
        print(output)
    
    if coverage and success:
        print("\n📊 Coverage report generated in tests/htmlcov/")
    
    return success


def run_validation_tests() -> bool:
    """Run API validation"""
    print("🔍 Running API validation...")
    
    # Run the validate.py script
    cmd = ["python", "validate.py", "--sync"]
    success, output = run_command(cmd, "API validation")
    
    if output:
        print(output)
    
    return success


def run_import_tests() -> bool:
    """Test that all modules can be imported"""
    print("📦 Testing module imports...")
    
    modules_to_test = [
        "config",
        "database", 
        "dependencies",
        "main",
        "models",
        "services",
        "routes",
        "utils",
        "factories"
    ]
    
    failed_imports = []
    
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"  ✅ {module}")
        except ImportError as e:
            print(f"  ❌ {module}: {e}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"❌ Failed to import: {', '.join(failed_imports)}")
        return False
    
    print("✅ All modules imported successfully")
    return True


def run_style_checks() -> bool:
    """Run code style checks"""
    checks_passed = 0
    total_checks = 0
    
    # Check if style tools are available
    style_tools = {
        "black": "Code formatting check",
        "flake8": "Linting check", 
        "isort": "Import sorting check"
    }
    
    for tool, description in style_tools.items():
        total_checks += 1
        try:
            # Check if tool is available
            result = subprocess.run([tool, "--version"], capture_output=True)
            if result.returncode == 0:
                # Run the actual check
                if tool == "black":
                    cmd = ["black", "--check", "--diff", "../"]
                elif tool == "flake8":
                    cmd = ["flake8", "../", "--max-line-length=100", "--extend-ignore=E203,W503"]
                elif tool == "isort":
                    cmd = ["isort", "--check-only", "--diff", "../"]
                
                success, output = run_command(cmd, description)
                if success:
                    checks_passed += 1
                elif output and "would reformat" not in output.lower():
                    print(f"   Issues found:\n{output}")
            else:
                print(f"  ⚠️  {tool} not available - install with: pip install {tool}")
        except FileNotFoundError:
            print(f"  ⚠️  {tool} not available - install with: pip install {tool}")
    
    if total_checks == 0:
        print("⚠️  No style checking tools available")
        return True
    
    if checks_passed == total_checks:
        print(f"✅ All {total_checks} style checks passed")
        return True
    else:
        print(f"❌ {checks_passed}/{total_checks} style checks passed")
        return False


def run_performance_tests() -> bool:
    """Run basic performance tests"""
    print("⚡ Running basic performance tests...")
    
    try:
        # Test import performance
        start_time = time.time()
        import main
        import_time = time.time() - start_time
        
        print(f"  📦 Module import time: {import_time:.3f}s")
        
        if import_time < 2.0:
            print("  ✅ Import performance acceptable")
            return True
        else:
            print("  ⚠️  Import performance slow")
            return False
            
    except Exception as e:
        print(f"  ❌ Performance test failed: {e}")
        return False


def run_security_audit() -> bool:
    """Run security audit with bandit if available"""
    print("🔒 Running security audit...")
    
    try:
        # Check if bandit is available
        result = subprocess.run(["bandit", "--version"], capture_output=True)
        if result.returncode != 0:
            print("  ⚠️  bandit not available - install with: pip install bandit")
            return True  # Not a failure, just not available
        
        # Run bandit security check
        cmd = ["bandit", "-r", "../", "-x", "../tests/", "-f", "txt"]
        success, output = run_command(cmd, "Security audit")
        
        if success:
            print("  ✅ No security issues found")
        else:
            print("  ⚠️  Security issues detected:")
            print(output)
        
        return success
        
    except FileNotFoundError:
        print("  ⚠️  bandit not available - install with: pip install bandit")
        return True


def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(description="OpenDocSeal API Test Runner")
    
    parser.add_argument("--module", choices=["security", "logging", "rate_limiting", "database"],
                       help="Run tests for specific module")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--validation", action="store_true", help="Run API validation only")
    parser.add_argument("--imports", action="store_true", help="Test module imports only")
    parser.add_argument("--style", action="store_true", help="Run style checks only")
    parser.add_argument("--performance", action="store_true", help="Run performance tests")
    parser.add_argument("--security", action="store_true", help="Run security audit")
    parser.add_argument("--quick", action="store_true", help="Run quick validation and import tests")
    
    args = parser.parse_args()
    
    print("🧪 OpenDocSeal API Test Runner")
    print("=" * 50)
    
    # Check test environment first
    if not check_test_environment():
        print("❌ Test environment not ready")
        return 1
    
    passed_tests = 0
    total_tests = 0
    
    # Run specific tests based on arguments
    if args.validation:
        total_tests += 1
        if run_validation_tests():
            passed_tests += 1
            
    elif args.imports:
        total_tests += 1
        if run_import_tests():
            passed_tests += 1
            
    elif args.style:
        total_tests += 1
        if run_style_checks():
            passed_tests += 1
            
    elif args.performance:
        total_tests += 1
        if run_performance_tests():
            passed_tests += 1
            
    elif args.security:
        total_tests += 1
        if run_security_audit():
            passed_tests += 1
            
    elif args.quick:
        print("🚀 Running quick tests (validation + imports)...")
        tests = [run_validation_tests, run_import_tests]
        for test in tests:
            total_tests += 1
            if test():
                passed_tests += 1
                
    elif args.module:
        # Run specific module tests
        total_tests += 1
        if args.module == "security":
            if run_security_tests(args.verbose):
                passed_tests += 1
        elif args.module == "logging":
            if run_logging_tests(args.verbose):
                passed_tests += 1
        elif args.module == "rate_limiting":
            if run_rate_limiting_tests(args.verbose):
                passed_tests += 1
        elif args.module == "database":
            if run_database_tests(args.verbose):
                passed_tests += 1
                
    elif args.all:
        print("🏃 Running comprehensive test suite...")
        
        # Pre-flight checks
        tests = [
            ("API Validation", run_validation_tests),
            ("Module Imports", run_import_tests),
            ("All Unit Tests", lambda: run_all_tests(args.verbose, args.coverage)),
            ("Style Checks", run_style_checks),
            ("Performance Tests", run_performance_tests),
            ("Security Audit", run_security_audit)
        ]
        
        for test_name, test_func in tests:
            total_tests += 1
            print(f"\n📝 Running {test_name}...")
            if test_func():
                passed_tests += 1
            else:
                print(f"❌ {test_name} failed")
    
    else:
        # Default: run basic tests
        print("🏃 Running default test suite...")
        tests = [
            ("API Validation", run_validation_tests),
            ("Module Imports", run_import_tests),
            ("Unit Tests", lambda: run_all_tests(args.verbose, args.coverage))
        ]
        
        for test_name, test_func in tests:
            total_tests += 1
            if test_func():
                passed_tests += 1
    
    # Print summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    print(f"✅ Tests passed: {passed_tests}/{total_tests}")
    
    if passed_tests == total_tests:
        print("🎉 All tests passed!")
        
        if args.coverage:
            print("\n📊 Coverage report: tests/htmlcov/index.html")
        
        print("\n💡 Next steps:")
        print("   • Start the API: python run.py")
        print("   • Run specific tests: python tests/run_tests.py --module security")
        print("   • Generate coverage: python tests/run_tests.py --all --coverage")
        
        return 0
    else:
        print("❌ Some tests failed!")
        print("\n🔧 Troubleshooting:")
        print("   • Check error messages above")
        print("   • Install missing dependencies: pip install -r requirements-test.txt")
        print("   • Run validation: python validate.py")
        print("   • Run specific module: python tests/run_tests.py --module <module>")
        
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)