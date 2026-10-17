#!/usr/bin/env python3
"""
Standalone entry point for PyInstaller / direct execution.

Use this file as the PyInstaller entry script to avoid relative-import issues.
"""

from __future__ import annotations

import sys


def main() -> int:
    from vttoolz.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
