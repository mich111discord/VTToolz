"""Allow running as python -m vttoolz and as frozen PyInstaller exe."""

from __future__ import annotations

import sys


def _run() -> int:
    # When frozen by PyInstaller, relative imports break.
    try:
        from vttoolz.cli import main
    except ImportError:
        from .cli import main  # type: ignore
    return main()


if __name__ == "__main__":
    sys.exit(_run())
