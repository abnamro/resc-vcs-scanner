from copy import deepcopy
from re import sub
from unittest import TestCase

from vcs_scanner.input_parser import _parse_vcs_instances_contents
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
