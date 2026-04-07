"""
Obelisk: Quick-launch entry point.

This file provides a simple way to run Obelisk without installing it 
via pip. It redirects directly to the core CLI runner.
"""
from __future__ import annotations
import sys
from obeliskscan.cli.run import main

if __name__ == "__main__":
    main()
