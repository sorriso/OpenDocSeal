"""
Path: infrastructure/source/api/tests/__init__.py
Version: 1
"""

import os
import sys

# Add parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

__version__ = "1.0.0"
__description__ = "OpenDocSeal API Utils Tests"