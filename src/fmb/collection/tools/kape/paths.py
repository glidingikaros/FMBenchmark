from __future__ import annotations

from pathlib import Path

_KAPE_PACKAGE_DIR = Path(__file__).resolve().parent
BUNDLED_KAPE_ASSETS_DIR = _KAPE_PACKAGE_DIR / "assets"
KAPEFILES_DIR = BUNDLED_KAPE_ASSETS_DIR / "kapefiles"
KAPE_BOUNDED_USER_BMP_TARGET = (
    BUNDLED_KAPE_ASSETS_DIR / "targets" / "FMBBoundedUserBMP.tkape"
)
KAPE_SETUPAPI_LOGS_TARGET = (
    BUNDLED_KAPE_ASSETS_DIR / "targets" / "FMBSetupApiLogs.tkape"
)
BUNDLED_KAPE_TARGETS = {
    "FMBBoundedUserBMP": KAPE_BOUNDED_USER_BMP_TARGET,
    "FMBSetupApiLogs": KAPE_SETUPAPI_LOGS_TARGET,
}
