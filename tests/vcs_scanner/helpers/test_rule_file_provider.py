# First Party
# Standard Library
import contextlib
import os
from pathlib import Path
import pytest

# First Party
from vcs_scanner.helpers.rule_file_provider import RuleFileProvider

THIS_DIR = Path(__file__).parent.parent
TOML_RULE_PATH = THIS_DIR.parent / "fixtures/rules.toml"
TOML_EMPTY_PATH = THIS_DIR.parent / "fixtures/rules_empty.toml"
TOML_SCAN_DIR_ONLY_PATH = THIS_DIR.parent / "fixtures/rules_scan_as_dir_only.toml"
TOML_SCAN_MIXED_PATH = THIS_DIR.parent / "fixtures/rules_mixed.toml"

TOML_TMP_FILE_SCAN_AS_DIR = THIS_DIR.parent / "fixtures/tmp_rules_scan_as_dir.toml"
TOML_TMP_FILE_SCAN_AS_REPO = THIS_DIR.parent / "fixtures/tmp_rules_scan_as_repo.toml"


def clean():
    with contextlib.suppress(FileNotFoundError):
        os.remove(TOML_TMP_FILE_SCAN_AS_DIR)
    with contextlib.suppress(FileNotFoundError):
        os.remove(TOML_TMP_FILE_SCAN_AS_REPO)

@pytest.fixture()
def resource(request):
    # Remove tmp files if exists.
    clean()
    request.addfinalizer(clean)

def test_rule_file_provider_constructor(resource):
    provider = RuleFileProvider(TOML_RULE_PATH)
    assert provider.scan_as_repo_rule_file_path is None
    assert provider.scan_as_dir_rule_file_path is None


def test_rule_file_provider_no_rules(resource):
    provider = RuleFileProvider(TOML_EMPTY_PATH)
    provider.init(TOML_TMP_FILE_SCAN_AS_REPO, TOML_TMP_FILE_SCAN_AS_DIR)
    assert provider.scan_as_repo_rule_file_path is None
    assert not os.path.exists(TOML_TMP_FILE_SCAN_AS_REPO)
    assert provider.scan_as_dir_rule_file_path is None
    assert not os.path.exists(TOML_TMP_FILE_SCAN_AS_DIR)


def test_rule_file_provider_rules_repo(resource):
    provider = RuleFileProvider(TOML_RULE_PATH)
    provider.init(TOML_TMP_FILE_SCAN_AS_REPO, TOML_TMP_FILE_SCAN_AS_DIR)
    assert provider.scan_as_repo_rule_file_path is not None
    assert os.path.exists(TOML_TMP_FILE_SCAN_AS_REPO)
    assert provider.scan_as_dir_rule_file_path is None
    assert not os.path.exists(TOML_TMP_FILE_SCAN_AS_DIR)

def test_rule_file_provider_rules_scan_as_dir(resource):
    provider = RuleFileProvider(TOML_SCAN_DIR_ONLY_PATH)
    provider.init(TOML_TMP_FILE_SCAN_AS_REPO, TOML_TMP_FILE_SCAN_AS_DIR)
    assert provider.scan_as_repo_rule_file_path is None
    assert not os.path.exists(TOML_TMP_FILE_SCAN_AS_REPO)
    assert provider.scan_as_dir_rule_file_path is not None
    assert os.path.exists(TOML_TMP_FILE_SCAN_AS_DIR)

def test_rule_file_provider_rules_mixed(resource):
    provider = RuleFileProvider(TOML_SCAN_MIXED_PATH)
    provider.init(TOML_TMP_FILE_SCAN_AS_REPO, TOML_TMP_FILE_SCAN_AS_DIR)
    assert provider.scan_as_repo_rule_file_path is not None
    assert os.path.exists(TOML_TMP_FILE_SCAN_AS_REPO)
    assert provider.scan_as_dir_rule_file_path is not None
    assert os.path.exists(TOML_TMP_FILE_SCAN_AS_DIR)
