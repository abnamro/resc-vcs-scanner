from unittest import TestCase
from vcs_scanner.common import tag_list_addition


def test_tag_addition_empty_list():
    dest: list[str] = []
    src: list[str] = ["Cli-only", "Sentinel"]
    result = tag_list_addition(dest, src)
    assert result == ["Cli-only", "Sentinel"]


def test_tag_addition_none():
    dest: list[str] = None
    src: list[str] = ["Cli-only", "Sentinel"]
    result = tag_list_addition(dest, src)
    assert result == ["Cli-only", "Sentinel"]


def test_tag_addition_both_none():
    result = tag_list_addition(None, None)
    assert result is None


def test_tag_addition_duplicate():
    case = TestCase()
    duplicate = ["Cli-only", "Github", "Azure"]
    result = tag_list_addition(duplicate, duplicate)
    case.assertCountEqual(duplicate, result)


def test_tag_addition():
    case = TestCase()
    dest: list[str] = ["Cli-only", "Github-only"]
    src: list[str] = ["Cli-only", "Sentinel"]
    result = tag_list_addition(dest, src)
    case.assertCountEqual(["Cli-only", "Sentinel", "Github-only"], result)
