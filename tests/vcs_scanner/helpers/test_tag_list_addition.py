from unittest import TestCase

from vcs_scanner.common import join_tag_lists


def test_tag_addition_empty_list():
    dest: list[str] = []
    src: list[str] = ["Cli-only", "Sentinel"]
    result = join_tag_lists(dest, src)
    assert result == ["Cli-only", "Sentinel"]


def test_tag_addition_none():
    dest: list[str] = None
    src: list[str] = ["Cli-only", "Sentinel"]
    result = join_tag_lists(dest, src)
    assert result == ["Cli-only", "Sentinel"]


def test_tag_addition_both_none():
    result = join_tag_lists(None, None)
    assert result is None


def test_tag_addition_duplicate():
    case = TestCase()
    duplicate = ["Cli-only", "Github", "Azure"]
    result = join_tag_lists(duplicate, duplicate)
    case.assertCountEqual(duplicate, result)


def test_tag_addition():
    case = TestCase()
    dest: list[str] = ["Cli-only", "Github-only"]
    src: list[str] = ["Cli-only", "Sentinel"]
    result = join_tag_lists(dest, src)
    case.assertCountEqual(["Cli-only", "Sentinel", "Github-only"], result)
