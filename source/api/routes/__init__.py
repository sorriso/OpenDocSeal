"""
Path: infrastructure/source/api/routes/__init__.py
Version: 3
"""

import auth
import documents  
import health
import test_control

__all__ = [
    "auth",
    "documents", 
    "health",
    "test_control"
]

# Package metadata
__version__ = "2.0.0"
__description__ = "FastAPI routes for OpenDocSeal API - Document notarization with blockchain timestamping"