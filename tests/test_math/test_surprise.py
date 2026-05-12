"""
KDE Surprise Detection Tests
===========================

Unit tests for the Kernel Density Estimation surprise detection engine.
Tests novelty detection, threshold classification, and bandwidth computation.
"""

import numpy as np
import pytest
from unittest.mock import patch, Mock
from typing import Dict, Any

# Import the module under test
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from backend.math_engines.surprise import (
    SurpriseDetector,
    compute_surprise
)


class TestSurpriseDetector:
    """Test the main SurpriseDetector class."""

