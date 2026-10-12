"""What the tests that start PowerShell share."""
from __future__ import annotations

import shutil

import pytest

PWSH = shutil.which("pwsh")
# A hang guard, not a speed check: loaded Windows runners have taken 45-54 s to start pwsh and compile Add-Type.
PWSH_TIMEOUT = 120
requires_pwsh = pytest.mark.skipif(PWSH is None, reason="PowerShell is not installed")
