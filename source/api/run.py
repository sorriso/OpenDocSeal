#!/usr/bin/env python3
"""
Path: infrastructure/source/api/run.py
Version: 3
"""

import uvicorn
import os
import sys
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Import after path setup
from config import get_settings


def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 11):
        print("❌ Python 3.11+ required")
        print(f"   Current version: {sys.version}")
        print("   Please upgrade Python and try again")
        return False
    return True


def check_dependencies():
    """Check if all required dependencies are available"""
    required_modules = [
        "fastapi",
        "uvicorn", 
        "motor",
        "pymongo",
        "minio",
        "pydantic",
        "pydantic_settings",  # FIXED: Check for pydantic-settings
        "bcrypt",
        "jwt",
        "structlog",  # FIXED: Check for structlog
        "email_validator"
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print("❌ Missing required dependencies:")
        for module in missing_modules:
            print(f"   - {module}")
        print("\n💡 Install missing dependencies with:")
        print("   pip install -r requirements.txt")
        return False
    
    return True


def validate_environment():
    """Validate the runtime environment"""
    # Check Python version
    if not check_python_version():
        return False
    
    # Check dependencies
    if not check_dependencies():
        return False
    
    # Check if running in virtual environment (warning only)
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("💡 Tip: Consider using a virtual environment")
        print("   python -m venv venv")
        print("   source venv/bin/activate  # On Windows: venv\\Scripts\\activate")
        print()
    
    return True


def validate_configuration(settings):
    """Validate application configuration"""
    validation_errors = []
    warnings = []
    
    # Check secret key strength
    if len(settings.secret_key) < 32:
        validation_errors.append("SECRET_KEY must be at least 32 characters long")
    
    if settings.secret_key in [
        "your-secret-key-change-this-in-production",
        "your-super-secret-key-change-this-in-production-min-32-chars"
    ]:
        validation_errors.append("SECRET_KEY is using default value - change it for security")
    
    # Check database URL format
    if not settings.mongodb_url.startswith(("mongodb://", "mongodb+srv://")):
        validation_errors.append("MONGODB_URL must start with 'mongodb://' or 'mongodb+srv://'")
    
    # Check MinIO configuration
    if not settings.minio_endpoint:
        validation_errors.append("MINIO_ENDPOINT is required")
    
    if not settings.minio_access_key or not settings.minio_secret_key:
        validation_errors.append("MINIO_ACCESS_KEY and MINIO_SECRET_KEY are required")
    
    # Check JWT configuration
    if settings.access_token_expire_minutes < 1:
        validation_errors.append("ACCESS_TOKEN_EXPIRE_MINUTES must be at least 1")
    
    # Warnings for development
    if settings.debug and settings.environment == "production":
        warnings.append("Debug mode is enabled in production environment")
    
    if settings.environment == "production" and settings.log_level.upper() == "DEBUG":
        warnings.append("Debug log level in production may impact performance")
    
    if settings.is_production and not os.getenv("SSL_CERT_PATH"):
        warnings.append("No SSL certificate configured for production")
    
    return validation_errors, warnings


def main():
    """Run the development server with comprehensive configuration validation"""
    
    # Pre-flight checks
    print("🔍 Performing pre-flight checks...")
    print()
    
    if not validate_environment():
        return 1
    
    # Load settings after validation
    try:
        settings = get_settings()
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return 1
    
    print("🚀 Starting OpenDocSeal API Development Server")
    print("=" * 60)
    print(f"📱 Environment: {settings.environment}")
    print(f"🧪 Test Mode: {settings.test_mode}")
    print(f"🌐 Host: {settings.api_host}:{settings.api_port}")
    print(f"🔧 Debug: {settings.debug}")
    print(f"📚 API Docs: http://{settings.api_host}:{settings.api_port}/docs")
    
    if settings.test_mode:
        print(f"🧪 Test Control: http://{settings.api_host}:{settings.api_port}{settings.test_api_prefix}")
    
    print("=" * 60)
    print()
    
    # Check required environment variables
    required_vars = [
        "SECRET_KEY",
        "MONGODB_URL", 
        "MINIO_ENDPOINT",
        "MINIO_ACCESS_KEY",
        "MINIO_SECRET_KEY"
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print()
        print("💡 Please configure the required variables in your .env file")
        print("   Example configuration available in the README or documentation")
        return 1
    
    # Validate configuration
    validation_errors, warnings = validate_configuration(settings)
    
    if validation_errors:
        print("❌ Configuration errors:")
        for error in validation_errors:
            print(f"   - {error}")
        print()
        print("🔧 Please fix the configuration errors above before starting the server")
        return 1
    
    if warnings:
        print("⚠️ Configuration warnings:")
        for warning in warnings:
            print(f"   - {warning}")
        print()
        print("💡 Consider addressing these warnings for production deployment")
        print()
    
    # Server configuration summary
    print("📋 Server Configuration:")
    print(f"   - Blockchain Mode: {settings.blockchain_mode}")
    print(f"   - Storage Mode: {settings.storage_mode}")
    print(f"   - Auth Mode: {settings.auth_mode}")
    print(f"   - Database: {settings.effective_mongodb_db_name}")
    print(f"   - Storage Bucket: {settings.effective_minio_bucket_name}")
    print(f"   - Rate Limiting: {'Enabled' if settings.rate_limit_enabled else 'Disabled'}")
    print(f"   - Correlation Logging: {'Enabled' if settings.log_correlation else 'Disabled'}")
    print()
    
    # Run the server
    try:
        # FIXED: Configure uvicorn settings with 0.37.0+ compatibility
        uvicorn_config = {
            "app": "main:app",
            "host": settings.api_host,
            "port": settings.api_port,
            "reload": settings.debug and not settings.test_mode,  # Disable reload in test mode
            "log_level": settings.log_level.lower(),
            "access_log": True,
            "loop": "asyncio",
            # FIXED: New uvicorn 0.37.0+ options
            "use_colors": not settings.is_production,  # Colorized logs in development
            "reload_dirs": ["."] if settings.debug else None,
            "reload_excludes": ["logs", "*.log", "*.sqlite", "*.db"] if settings.debug else None,
            # FIXED: Enhanced logging configuration
            "log_config": {
                "version": 1,
                "disable_existing_loggers": False,
                "formatters": {
                    "default": {
                        "()": "uvicorn.logging.DefaultFormatter",
                        "fmt": "%(levelprefix)s %(message)s",
                        "use_colors": not settings.is_production,
                    },
                    "access": {
                        "()": "uvicorn.logging.AccessFormatter",
                        "fmt": "%(levelprefix)s %(client_addr)s - '%(request_line)s' %(status_code)s",
                    },
                },
                "handlers": {
                    "default": {
                        "formatter": "default",
                        "class": "logging.StreamHandler",
                        "stream": "ext://sys.stdout",
                    },
                    "access": {
                        "formatter": "access",
                        "class": "logging.StreamHandler",
                        "stream": "ext://sys.stdout",
                    },
                },
                "loggers": {
                    "uvicorn": {"handlers": ["default"], "level": settings.log_level.upper()},
                    "uvicorn.error": {"level": settings.log_level.upper()},
                    "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
                },
            }
        }
        
        # Add SSL configuration if available in production
        if settings.is_production and os.getenv("SSL_CERT_PATH") and os.getenv("SSL_KEY_PATH"):
            uvicorn_config.update({
                "ssl_certfile": os.getenv("SSL_CERT_PATH"),
                "ssl_keyfile": os.getenv("SSL_KEY_PATH")
            })
            print("🔒 SSL enabled")
        
        # FIXED: Add development vs production specific settings
        if settings.debug:
            # Development settings
            uvicorn_config.update({
                "reload_delay": 0.25,  # Faster reload in development
                "workers": 1,  # Single worker for debugging
            })
        else:
            # Production settings
            uvicorn_config.update({
                "workers": 1,  # Still single worker for development server
                "access_log": settings.log_level.upper() in ["DEBUG", "INFO"],
            })
        
        print("✅ Starting server...")
        print(f"🌐 Server will be available at: http://{settings.api_host}:{settings.api_port}")
        if settings.debug:
            print(f"📖 API documentation: http://{settings.api_host}:{settings.api_port}/docs")
            print(f"📋 Alternative docs: http://{settings.api_host}:{settings.api_port}/redoc")
        print()
        print("Press Ctrl+C to stop the server")
        print("-" * 60)
        
        # FIXED: Enhanced uvicorn run with better error handling for 0.37.0+
        uvicorn.run(**uvicorn_config)
        
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
        return 0
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"❌ Port {settings.api_port} is already in use!")
            print("   Try using a different port with API_PORT environment variable")
            print(f"   Example: API_PORT=8001 python run.py")
        else:
            print(f"❌ Failed to start server: {e}")
        return 1
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure all dependencies are installed: pip install -r requirements.txt")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error starting server: {e}")
        print("   Check your configuration and try again")
        if settings.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    # Run the main server
    exit_code = main()
    sys.exit(exit_code)