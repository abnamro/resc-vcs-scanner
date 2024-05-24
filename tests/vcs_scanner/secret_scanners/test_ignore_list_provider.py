# Standard Library
from pathlib import Path

# First Party
from vcs_scanner.helpers.providers.ignore_list import IgnoredListProvider

THIS_DIR = Path(__file__).parent.parent


# We check that given a file, we get only 1 line:
def test_ignore_list_provider():
    ignore_list_path = THIS_DIR.parent / "fixtures/ignore-findings-list.dsv"
    list_provider = IgnoredListProvider(str(ignore_list_path))
    assert {
        "active_path|active_rule|57": True,
        "active_path_2|active_rule_2|58": True,
    } == list_provider.get_ignore_list()
