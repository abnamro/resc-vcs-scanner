# Standard Library
import os
from pathlib import Path
from unittest import mock

# Third Party
import pytest

# First Party
from vcs_scanner.common import get_rule_pack_version_from_file, load_vcs_instances

read_data = "{}"
mock_open = mock.mock_open(read_data=read_data)

THIS_DIR = Path(__file__).parent


def test_parse_vcs_instances_file():
    my_data_path = THIS_DIR.parent / "fixtures/working_vcs_instances.json"
    with mock.patch.dict(
        os.environ,
        {"VCS_INSTANCE_TOKEN": "token123", "VCS_INSTANCE_USERNAME": "user123"},
    ):
        vcs_instances = load_vcs_instances(str(my_data_path))
    assert vcs_instances.get("vcs_instance_1").provider_type == "AZURE_DEVOPS"
    assert vcs_instances.get("vcs_instance_1").port == 443
    assert vcs_instances.get("vcs_instance_1").name == "vcs_instance_1"
    assert vcs_instances.get("vcs_instance_1").exceptions == []
    assert vcs_instances.get("vcs_instance_1").hostname == "dev.azure.com"
    assert vcs_instances.get("vcs_instance_1").scheme == "https"
    assert vcs_instances.get("vcs_instance_1").username == "user123"
    assert vcs_instances.get("vcs_instance_1").token == "token123"
    assert vcs_instances.get("vcs_instance_1").scope == []
    assert vcs_instances.get("vcs_instance_1").organization == "org"

    assert vcs_instances.get("vcs_instance_2").provider_type == "BITBUCKET"
    assert vcs_instances.get("vcs_instance_2").port == 1234
    assert vcs_instances.get("vcs_instance_2").name == "vcs_instance_2"
    assert vcs_instances.get("vcs_instance_2").exceptions == []
    assert vcs_instances.get("vcs_instance_2").hostname == "bitbucket.com"
    assert vcs_instances.get("vcs_instance_2").scheme == "https"
    assert vcs_instances.get("vcs_instance_2").username == "user123"
    assert vcs_instances.get("vcs_instance_2").token == "token123"
    assert vcs_instances.get("vcs_instance_2").scope == []
    assert vcs_instances.get("vcs_instance_2").organization is None


def test_parse_vcs_instances_file_with_missing_org():
    my_data_path = THIS_DIR.parent / "fixtures/missing_org_ado_vcs_instances.json"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        load_vcs_instances(str(my_data_path))
        assert pytest_wrapped_e.value.code == -1


def test_get_rule_pack_version_from_file():
    rules_path = THIS_DIR.parent / "fixtures/rules.toml"
    with open(rules_path, encoding="utf-8") as rule_pack:
        assert "2.0.13" == get_rule_pack_version_from_file(rule_pack.read())
