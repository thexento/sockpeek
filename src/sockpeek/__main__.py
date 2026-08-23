"""Entry point for python -m sockpeek execution."""

from __future__ import annotations

import sys
from sockpeek.cli import main

if __name__ == "__main__":
    sys.exit(main())