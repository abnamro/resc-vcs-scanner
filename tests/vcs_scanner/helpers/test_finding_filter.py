# Standard Library
from datetime import datetime

# Third Party
from resc_backend.resc_web_service.schema.finding import FindingCreate
from resc_backend.resc_web_service.schema.finding_status import FindingStatus

# First Party
from vcs_scanner.helpers.finding_filter import should_process_finding

finding = FindingCreate(
    scan_ids=[1],
    file_path=f"file_path_{1}",
    line_number=1,
    column_start=1,
    column_end=1,
    commit_id=f"commit_id_{1}",
    commit_message=f"commit_message_{1}",
    commit_timestamp=datetime.utcnow(),
    author=f"author_{1}",
    email=f"email_{1}",
    status=FindingStatus.NOT_ANALYZED,
    comment=f"comment_{1}",
    rule_name=f"rule_{1}",
    repository_id=1,
)


def test_finding_tag_filter_no_filter():
    result = should_process_finding(finding=finding, rule_tags={"rule_1": ["tag"]})
    assert result is True


def test_finding_tag_filter_match_include_filter():
    result = should_process_finding(
        finding=finding, rule_tags={"rule_1": ["tag"]}, include_tags=["tag"]
    )
    assert result is True


def test_finding_tag_filter_nomatch_include_filter():
    result = should_process_finding(
        finding=finding, rule_tags={"rule_1": ["tag"]}, include_tags=["resc"]
    )
    assert result is False


def test_finding_tag_filter_match_ignore_filter():
    result = should_process_finding(
        finding=finding, rule_tags={"rule_1": ["tag"]}, ignore_tags=["tag"]
    )
    assert result is False


def test_finding_tag_filter_nomatch_ignore_filter():
    result = should_process_finding(
        finding=finding, rule_tags={"rule_1": ["tag"]}, ignore_tags=["resc"]
    )
    assert result is True


def test_finding_tag_filter_match_both_filters():
    result = should_process_finding(
        finding=finding,
        rule_tags={"rule_1": ["tag"]},
        include_tags=["tag"],
        ignore_tags=["tag"],
    )
    assert result is False


def test_finding_tag_filter_nomatch_both_filters():
    result = should_process_finding(
        finding=finding,
        rule_tags={"rule_1": ["tag"]},
        include_tags=["resc"],
        ignore_tags=["resc"],
    )
    assert result is False
