"""Pytest configuration for USMD-RDSH test suite.

Supports Python 3.13, 3.14 and 3.15 via tox (see tox.ini).
"""

import logging
import sys
from pathlib import Path

# Ensure the project root is importable
root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))

logging.basicConfig(level=logging.WARNING)
# asyncio_mode = "strict" is set in pyproject.toml [tool.pytest.ini_options]
