"""
Reconnaissance AI Personality Package
=====================================

Bootstraps import paths so submodules can access EgoQT SQLAlchemy services
when running inside Docker containers or isolated environments.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


# Try to find ROOT_DIR (may not exist in kage-pro standalone)
try:
    ROOT_DIR = Path(__file__).resolve().parents[4]
    EGOQT_SRC = ROOT_DIR / "EgoQT" / "src"
    if not EGOQT_SRC.exists():
        EGOQT_SRC = None
except (IndexError, AttributeError):
    ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
    EGOQT_SRC = None

# For kage-pro, use project root
if EGOQT_SRC is None or not EGOQT_SRC.exists():
    # In kage-pro, use the project root
    ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
    EGOQT_SRC = None

data_dir_override = os.getenv("RECON_DATA_DIR")
if data_dir_override:
    candidate_path = Path(data_dir_override)
    if not candidate_path.is_absolute():
        candidate_path = (ROOT_DIR / candidate_path).resolve()
    DATA_DIR = candidate_path
else:
    DATA_DIR = Path(__file__).resolve().parent

DATA_DIR.mkdir(parents=True, exist_ok=True)

# Only add to path if they exist
for candidate in (str(ROOT_DIR),):
    if candidate not in sys.path and Path(candidate).exists():
        sys.path.insert(0, candidate)
if EGOQT_SRC and str(EGOQT_SRC) not in sys.path and EGOQT_SRC.exists():
    sys.path.insert(0, str(EGOQT_SRC))


__all__ = ["ROOT_DIR", "EGOQT_SRC", "DATA_DIR"]

# Register Django AppConfig
default_app_config = 'artificial_intelligence.personalities.reconnaissance.apps.ReconnaissanceConfig'
