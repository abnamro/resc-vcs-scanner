import os
from copy import deepcopy
from re import sub
from unittest import TestCase
from pathlib import Path

# Third Party
from mock import mock

# First Party
from vcs_scanner.input_parser import _parse_vcs_instances_contents, parse_vcs_instances_file
from vcs_scanner.model import VCSInstanceRuntime

vcs_instances_json_base = """
    {
      "AZURE_DEVOPS": {
        "name": "AZURE_DEVOPS",
        "exceptions": [],
        "provider_type": "AZURE_DEVOPS",
        "hostname": "dev.azure.com",
        "port": "443",
        "scheme": "https",
        "username": "AZURE_DEVOPS_USERNAME",
        "token": "AZURE_DEVOPS_TOKEN",
        "scope": ["GRD000DUMMY"],
        "organization": "cbsp-abnamro"
      }
    }
"""

vcs_instances_expected_base: list[VCSInstanceRuntime] = [
    VCSInstanceRuntime(
        name="AZURE_DEVOPS",
        provider_type="AZURE_DEVOPS",
        hostname="dev.azure.com",
        port=443,
        scheme="https",
        username="AZURE_DEVOPS_USERNAME",
        token="AZURE_DEVOPS_TOKEN",
        exceptions=[],
        scope=["GRD000DUMMY"],
        organization="cbsp-abnamro",
        include_tags=[],
        ignore_tags=[],
    )
]
read_data = "{}"
mock_open = mock.mock_open(read_data=read_data)

THIS_DIR = Path(__file__).parent

def test_parse_vcs_instances_null():
    vcs_instances_actual: list[VCSInstanceRuntime] = []
    vcs_instances_json_null = sub(
        '"cbsp-abnamro"',
        """"cbsp-abnamro",
           "include_tags": null,
           "ignore_tags": null""",
        vcs_instances_json_base,
    )

    result = _parse_vcs_instances_contents(vcs_instances_json_null, vcs_instances_actual)

    case: TestCase = TestCase()
    case.assertCountEqual(vcs_instances_expected_base, vcs_instances_actual)
    assert result is False


def test_parse_vcs_instances_empty_tag_lists():
    vcs_instances_actual: list[VCSInstanceRuntime] = []
    vcs_instances_json_empty = sub(
        '"cbsp-abnamro"',
        """"cbsp-abnamro",
           "include_tags": [],
           "ignore_tags": []""",
        vcs_instances_json_base,
    )

    result = _parse_vcs_instances_contents(vcs_instances_json_empty, vcs_instances_actual)

    case: TestCase = TestCase()
    case.assertCountEqual(vcs_instances_expected_base, vcs_instances_actual)
    assert result is False


def test_parse_vcs_instances_no_tag_lists():
    vcs_instances_actual: list[VCSInstanceRuntime] = []
    result = _parse_vcs_instances_contents(vcs_instances_json_base, vcs_instances_actual)

    case: TestCase = TestCase()
    case.assertCountEqual(vcs_instances_expected_base, vcs_instances_actual)
    assert result is False


def test_parse_vcs_instances():
    vcs_instances_actual: list[VCSInstanceRuntime] = []
    vcs_instances_json_full = sub(
        '"cbsp-abnamro"',
        """"cbsp-abnamro",
           "include_tags": ["Cli-only", "Github", "Azure"],
           "ignore_tags": ["Bitbucket", "Sentinel"]""",
        vcs_instances_json_base,
    )
    vcs_instances_expected_full: list[VCSInstanceRuntime] = deepcopy(vcs_instances_expected_base)
    vcs_instances_expected_full[0].include_tags = ["Cli-only", "Github", "Azure"]
    vcs_instances_expected_full[0].ignore_tags = ["Bitbucket", "Sentinel"]

    result = _parse_vcs_instances_contents(vcs_instances_json_full, vcs_instances_actual)

    case: TestCase = TestCase()
    case.assertCountEqual(vcs_instances_expected_full, vcs_instances_actual)
    assert result is False



def test_parse_vcs_instances_file():
    my_data_path = THIS_DIR.parent / "fixtures/working_vcs_instances.json"
    with mock.patch.dict(
            os.environ,
            {"VCS_INSTANCE_TOKEN": "token123", "VCS_INSTANCE_USERNAME": "user123"},
    ):
        vcs_instances = parse_vcs_instances_file(str(my_data_path))
    assert vcs_instances[0].provider_type == "AZURE_DEVOPS"
    assert vcs_instances[0].port == 443
    assert vcs_instances[0].name == "vcs_instance_1"
    assert vcs_instances[0].exceptions == []
    assert vcs_instances[0].hostname == "dev.azure.com"
    assert vcs_instances[0].scheme == "https"
    assert vcs_instances[0].username == "user123"
    assert vcs_instances[0].token == "token123"
    assert vcs_instances[0].scope == []
    assert vcs_instances[0].organization == "org"

    assert vcs_instances[1].provider_type == "BITBUCKET"
    assert vcs_instances[1].port == 1234
    assert vcs_instances[1].name == "vcs_instance_2"
    assert vcs_instances[1].exceptions == []
    assert vcs_instances[1].hostname == "bitbucket.com"
    assert vcs_instances[1].scheme == "https"
    assert vcs_instances[1].username == "user123"
    assert vcs_instances[1].token == "token123"
    assert vcs_instances[1].scope == []
    assert vcs_instances[1].organization is None


def test_parse_vcs_instances_file_with_missing_org():
    my_data_path = THIS_DIR.parent / "fixtures/missing_org_ado_vcs_instances.json"
    assert [] == parse_vcs_instances_file(str(my_data_path))


def test_parse_vcs_instances_file_with_mal_formatted_file():
    my_data_path = THIS_DIR.parent / "fixtures/non_json.file"
    assert [] == parse_vcs_instances_file(str(my_data_path))


def test_parse_vcs_instances_file_with_missing_file():
    my_data_path = THIS_DIR.parent / "fixtures/non_there.file"
    assert [] == parse_vcs_instances_file(str(my_data_path))
