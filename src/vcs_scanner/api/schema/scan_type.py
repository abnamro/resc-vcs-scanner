# Standard Library
from enum import Enum

# First Party
from vcs_scanner.api.constants import BASE_SCAN, INCREMENTAL_SCAN


class ScanType(str, Enum):
    BASE = BASE_SCAN
    INCREMENTAL = INCREMENTAL_SCAN
