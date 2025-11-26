#!/usr/bin/env python3
"""
CTU-13 Dataset Analysis Tool - Main Entry Point

A comprehensive cybersecurity analysis tool for the CTU-13 botnet dataset.
"""

import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from ctu13_analyzer.cli import main

if __name__ == '__main__':
    main()