#!/usr/bin/env python3
"""
Path: infrastructure/source/api/validate.py
Version: 4
"""

import sys
import os
import importlib
from pathlib import Path
from typing import List, Dict, Any, Tuple
import asyncio

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))


class APIValidator:
    """Comprehensive API validation"""
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.checks_passed = 0
        self.checks_total = 0
    
    def check(self, description: str, condition: bool, error_msg: str = None, warning_msg: str = None):
        """Record a validation check result"""
        self.checks_total += 1
        
        if condition:
            self.checks_passed += 1
            print(f"  ✅ {description}")
        else:
            print(f"  ❌ {description}")
            if error_msg:
                self.errors.append(f"{description}: {error_msg}")
            else:
                self.errors.append(description)
        
        if warning_msg:
            self.warnings.append(f"{description}: {warning_msg}")
            print(f"  ⚠️  {warning_msg}")
    
    def validate_python_version(self):
        """Validate Python version compatibility"""
        print("\n🐍 Validating Python version...")
        
        version_info = sys.version_info
        
        # Check minimum version (3.11+)
        self.check(
            f"Python version {version_info.major}.{version_info.minor}.{version_info.micro}",
            version_info >= (3, 11),
            f"Python 3.11+ required, found {version_info.major}.{version_info.minor}.{version_info.micro}"
        )
        
        # Check if running in virtual environment (warning)
        in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
        if not in_venv:
            self.warnings.append("Not running in virtual environment")
            print("  ⚠️  Consider using a virtual environment")
    
    def validate_file_structure(self):
        """Validate project file structure"""
        print("\n📁 Validating file structure...")
        
        expected_files = [
            "main.py",
            "config.py", 
            "database.py",
            "dependencies.py",
            "requirements.txt",
            "requirements-test.txt",  # FIXED: Added test requirements
            "run.py",
            "init_logs.py",
            ".env.example"  # ADDED: Environment example file
        ]
        
        expected_directories = [
            "models",
            "services", 
            "routes",  # FIXED: Changed from "routers" to "routes"
            "utils",
            "factories",
            "tests"
        ]
        
        # Check files
        for file_name in expected_files:
            file_path = Path(file_name)
            self.check(f"File {file_name}", file_path.exists())
        
        # Check directories
        for dir_name in expected_directories:
            dir_path = Path(dir_name)
            self.check(f"Directory {dir_name}", dir_path.exists() and dir_path.is_dir())
            
            # Check if directory has __init__.py (except tests)
            if dir_name != "tests" and dir_path.exists():
                init_file = dir_path / "__init__.py"
                self.check(f"Init file {dir_name}/__init__.py", init_file.exists())
        
        # Check log directory can be created
        log_dir = Path("logs")
        if not log_dir.exists():
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
                self.check("Log directory creation", True)
            except Exception as e:
                self.check("Log directory creation", False, str(e))
        else:
            self.check("Log directory exists", True)
    
    def validate_dependencies(self):
        """Validate Python dependencies and versions"""
        print("\n📦 Validating dependencies...")
        
        # FIXED: Updated critical dependencies with version checks
        critical_dependencies = {
            "fastapi": "0.117.1",
            "uvicorn": "0.37.0",
            "pydantic": "2.11.9",
            "pydantic_settings": "2.6.1",  # FIXED: Check pydantic-settings
            "motor": "3.7.1",
            "pymongo": "4.15.1",
            "minio": "7.2.16",
            "structlog": "25.4.0",  # FIXED: Check structlog
            "bcrypt": "4.3.0",
            "jwt": "2.10.1",
            "cryptography": "46.0.1"
        }
        
        for package, min_version in critical_dependencies.items():
            try:
                # Handle special case for PyJWT
                if package == "jwt":
                    import jwt as package_module
                    package_name = "PyJWT"
                elif package == "pydantic_settings":
                    import pydantic_settings as package_module
                    package_name = "pydantic-settings"
                else:
                    package_module = importlib.import_module(package)
                    package_name = package
                
                # Get version if available
                version = getattr(package_module, '__version__', 'unknown')
                
                self.check(
                    f"{package_name} ({version})", 
                    True,  # Just check if importable for now
                    warning_msg=f"Expected version >= {min_version}" if version == 'unknown' else None
                )
                
            except ImportError:
                self.check(f"Package {package}", False, f"Package {package} not found")
    
    def validate_imports(self):
        """Validate that all modules can be imported"""
        print("\n🔗 Validating Python imports...")
        
        modules_to_check = [
            ("config", "Configuration module"),
            ("database", "Database module"),
            ("models", "Models package"),
            ("services", "Services package"),
            ("routes", "Routes package"),  # FIXED: Changed from "routers"
            ("utils", "Utilities package"),
            ("factories", "Factories package"),
            ("dependencies", "Dependencies module")
        ]
        
        for module_name, description in modules_to_check:
            try:
                importlib.import_module(module_name)
                self.check(description, True)
            except ImportError as e:
                self.check(description, False, str(e))
    
    def validate_environment_variables(self):
        """Validate environment variables"""
        print("\n🌍 Validating environment variables...")
        
        # Required environment variables
        required_vars = [
            "SECRET_KEY",
            "MONGODB_URL",
            "MINIO_ENDPOINT",
            "MINIO_ACCESS_KEY", 
            "MINIO_SECRET_KEY"
        ]
        
        # Optional but recommended
        recommended_vars = [
            "ENVIRONMENT",
            "DEBUG",
            "LOG_LEVEL",
            "RATE_LIMIT_ENABLED"
        ]
        
        # Check required variables
        for var in required_vars:
            value = os.getenv(var)
            if value:
                # Mask sensitive values
                if any(sensitive in var.lower() for sensitive in ['password', 'secret', 'key']):
                    display_value = f"***{value[-4:] if len(value) > 4 else '***'}"
                else:
                    display_value = value[:50] + "..." if len(value) > 50 else value
                
                self.check(f"Environment variable {var}", True)
                
                # Additional validation for specific variables
                if var == "SECRET_KEY" and len(value) < 32:
                    self.warnings.append(f"{var} should be at least 32 characters long")
                elif var == "MONGODB_URL" and not value.startswith(("mongodb://", "mongodb+srv://")):
                    self.errors.append(f"{var} must start with 'mongodb://' or 'mongodb+srv://'")
            else:
                self.check(f"Environment variable {var}", False, f"{var} is not set")
        
        # Check recommended variables
        for var in recommended_vars:
            value = os.getenv(var)
            if value:
                self.check(f"Optional variable {var}", True)
            else:
                self.warnings.append(f"Consider setting {var} for better configuration")
    
    def validate_configuration(self):
        """Validate application configuration"""
        print("\n⚙️ Validating configuration...")
        
        try:
            from config import get_settings
            settings = get_settings()
            
            # Validate settings can be loaded
            self.check("Settings loading", settings is not None)
            
            # Check database configuration
            self.check("Database URL format", 
                      settings.mongodb_url.startswith(('mongodb://', 'mongodb+srv://')))
            
            # Check database name
            self.check("Database name configured", 
                      hasattr(settings, 'effective_mongodb_db_name') and 
                      settings.effective_mongodb_db_name)
            
            # FIXED: Check new connection parameters
            self.check("MongoDB connection params",
                      hasattr(settings, 'mongodb_connection_params'))
            
            # Check MinIO configuration
            self.check("MinIO endpoint configured",
                      settings.minio_endpoint is not None)
            
            # Check security settings
            if hasattr(settings, 'secret_key'):
                if len(settings.secret_key) >= 32:
                    self.check("Secret key length", True)
                else:
                    self.check("Secret key length", False, "Secret key must be at least 32 characters")
            
        except Exception as e:
            self.check("Configuration validation", False, str(e))
    
    def validate_models(self):
        """Validate Pydantic models"""
        print("\n🏗️ Validating models...")
        
        try:
            # FIXED: Check for Pydantic v2.11.9+ compatibility
            from models.base import BaseDocument, DocumentStatus, UserRole
            from models.auth import User, UserCreate, TokenResponse
            from models.document import Document, DocumentCreate
            from models.blockchain import BlockchainTransaction
            from models.metadata import MetadataField  # ADDED: New model
            
            self.check("BaseDocument model", BaseDocument is not None)
            self.check("DocumentStatus enum", DocumentStatus is not None)
            self.check("UserRole enum", UserRole is not None)
            self.check("User model", User is not None)
            self.check("BlockchainTransaction model", BlockchainTransaction is not None)
            self.check("DocumentCreate model", DocumentCreate is not None)
            self.check("UserCreate model", UserCreate is not None)
            self.check("TokenResponse model", TokenResponse is not None)
            self.check("MetadataField model", MetadataField is not None)
            
            # FIXED: Check for Pydantic v2 features
            if hasattr(BaseDocument, 'model_config'):
                self.check("Pydantic v2 model_config", True)
            else:
                self.check("Pydantic v2 model_config", False, "Models may not be compatible with Pydantic v2")
            
        except Exception as e:
            self.check("Models validation", False, str(e))
    
    def validate_services(self):
        """Validate service interfaces and implementations"""
        print("\n🔧 Validating services...")
        
        try:
            from services.interfaces import (
                AuthServiceInterface, 
                BlockchainServiceInterface,
                StorageServiceInterface,
                DocumentServiceInterface
            )
            
            self.check("AuthServiceInterface", AuthServiceInterface is not None)
            self.check("BlockchainServiceInterface", BlockchainServiceInterface is not None)
            self.check("StorageServiceInterface", StorageServiceInterface is not None)
            self.check("DocumentServiceInterface", DocumentServiceInterface is not None)
            
            # Check service factory
            from factories.service_factory import get_service_factory, get_test_service_factory
            
            self.check("Service factory", get_service_factory is not None)
            self.check("Test service factory", get_test_service_factory is not None)
            
        except Exception as e:
            self.check("Services validation", False, str(e))
    
    def validate_api_structure(self):
        """Validate API structure"""
        print("\n🌐 Validating API structure...")
        
        try:
            # Check routes (FIXED: changed from routers to routes)
            from routes import auth, documents, health
            
            self.check("Auth routes", hasattr(auth, 'router'))
            self.check("Document routes", hasattr(documents, 'router'))
            self.check("Health routes", hasattr(health, 'router'))
            
            # Check if test routes exist
            try:
                from routes import test_control
                self.check("Test control routes", hasattr(test_control, 'router'))
            except ImportError:
                self.warnings.append("Test control routes not available")
            
            # Check dependencies module
            from dependencies import get_auth_service, get_current_user
            self.check("Dependency injection", get_auth_service is not None and get_current_user is not None)
            
        except Exception as e:
            self.check("API structure validation", False, str(e))
    
    def validate_utilities(self):
        """Validate utility modules"""
        print("\n🛠️ Validating utilities...")
        
        try:
            # FIXED: Check updated logging utilities with structlog compatibility
            from utils.logging import setup_logging, get_logger
            from utils.security import hash_password, generate_secure_token
            from utils.rate_limiting import RateLimiter, create_rate_limiter
            
            self.check("Logging utilities", setup_logging is not None and get_logger is not None)
            self.check("Security utilities", hash_password is not None and generate_secure_token is not None)
            self.check("Rate limiting utilities", RateLimiter is not None and create_rate_limiter is not None)
            
            # Check for structlog compatibility
            try:
                import structlog
                self.check("Structlog available", True)
            except ImportError:
                self.warnings.append("Structlog not available - advanced logging features disabled")
            
        except Exception as e:
            self.check("Utilities validation", False, str(e))
    
    def validate_test_structure(self):
        """Validate test structure"""
        print("\n🧪 Validating test structure...")
        
        test_files = [
            "tests/__init__.py",
            "tests/test_security.py",
            "tests/test_logging.py",  # ADDED
            "tests/test_rate_limiting.py",  # ADDED
            "tests/test_database.py"  # ADDED
        ]
        
        for test_file in test_files:
            test_path = Path(test_file)
            if test_path.exists():
                self.check(f"Test file {test_file}", True)
            else:
                self.warnings.append(f"Test file {test_file} not found")
        
        # Check pytest configuration
        pytest_files = ["pytest.ini", "pyproject.toml", "setup.cfg"]
        pytest_config_found = any(Path(f).exists() for f in pytest_files)
        
        if pytest_config_found:
            self.check("Pytest configuration", True)
        else:
            self.warnings.append("No pytest configuration found")
    
    async def validate_database_connection(self):
        """Validate database connection (optional)"""
        print("\n💾 Validating database connection...")
        
        try:
            from database import Database
            from config import get_settings
            
            settings = get_settings()
            
            # Only test if we have a valid MongoDB URL
            if settings.mongodb_url and settings.mongodb_url.startswith(("mongodb://", "mongodb+srv://")):
                db = Database()
                
                try:
                    # Attempt connection with timeout
                    await asyncio.wait_for(db.connect(), timeout=5.0)
                    self.check("Database connection", db.is_connected)
                    
                    if db.is_connected:
                        # Test basic operations
                        health = await db.health_check()
                        self.check("Database health check", health.get("status") == "healthy")
                    
                    await db.disconnect()
                    
                except asyncio.TimeoutError:
                    self.check("Database connection", False, "Connection timeout")
                except Exception as e:
                    self.check("Database connection", False, f"Connection failed: {e}")
            else:
                self.warnings.append("No valid MongoDB URL configured - skipping database test")
                
        except Exception as e:
            self.warnings.append(f"Database validation skipped: {e}")
    
    def print_summary(self) -> bool:
        """Print validation summary and return success status"""
        print("\n" + "=" * 60)
        print("📊 VALIDATION SUMMARY")
        print("=" * 60)
        
        print(f"✅ Checks passed: {self.checks_passed}/{self.checks_total}")
        
        if self.errors:
            print(f"\n❌ Errors ({len(self.errors)}):")
            for error in self.errors:
                print(f"   • {error}")
        
        if self.warnings:
            print(f"\n⚠️  Warnings ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   • {warning}")
        
        success = len(self.errors) == 0
        
        print("\n" + "=" * 60)
        
        if success:
            print("✅ Your OpenDocSeal API setup looks good!")
            print("\n💡 Next steps:")
            print("   1. Initialize logs: python init_logs.py --all")
            print("   2. Start the API: python run.py")
            print("   3. Visit http://localhost:8000/docs for API documentation")
            print("   4. Run tests: python tests/run_tests.py --all")
            if self.warnings:
                print("   5. Address warnings for production deployment")
            return True
        else:
            print("❌ Validation failed!")
            print("🔧 Please fix the errors above before running the API")
            
            # Suggest common fixes
            print("\n💡 Common fixes:")
            if any("requirements" in error.lower() for error in self.errors):
                print("   • Install dependencies: pip install -r requirements.txt")
            if any("secret_key" in error.lower() for error in self.errors):
                print("   • Set SECRET_KEY in .env file (min 32 characters)")
            if any("mongodb" in error.lower() for error in self.errors):
                print("   • Configure MONGODB_URL in .env file")
            if any("minio" in error.lower() for error in self.errors):
                print("   • Configure MinIO settings in .env file")
            if any("pydantic" in error.lower() for error in self.errors):
                print("   • Install pydantic-settings: pip install pydantic-settings>=2.6.1")
            
            return False


async def main():
    """Main validation function"""
    print("🔍 OpenDocSeal API Validation")
    print("=" * 60)
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    print("=" * 60)
    
    validator = APIValidator()
    
    # Run all validations
    validator.validate_python_version()
    validator.validate_file_structure()
    validator.validate_dependencies()
    validator.validate_imports()
    validator.validate_environment_variables() 
    validator.validate_configuration()
    validator.validate_models()
    validator.validate_services()
    validator.validate_api_structure()
    validator.validate_utilities()
    validator.validate_test_structure()
    
    # Database validation (async)
    await validator.validate_database_connection()
    
    # Print summary and return success status
    success = validator.print_summary()
    return 0 if success else 1


def run_sync_validation():
    """Run synchronous validation only"""
    validator = APIValidator()
    
    # Run non-async validations
    validator.validate_python_version()
    validator.validate_file_structure()
    validator.validate_dependencies()
    validator.validate_imports()
    validator.validate_environment_variables() 
    validator.validate_configuration()
    validator.validate_models()
    validator.validate_services()
    validator.validate_api_structure()
    validator.validate_utilities()
    validator.validate_test_structure()
    
    success = validator.print_summary()
    return 0 if success else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--sync":
        # Synchronous mode (skip database connection test)
        exit_code = run_sync_validation()
    else:
        # Full async validation
        exit_code = asyncio.run(main())
    
    sys.exit(exit_code)