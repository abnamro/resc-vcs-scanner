# Standard Library
from datetime import UTC, datetime
from pathlib import Path

# Third Party
from vcs_scanner.api.schema.finding import Finding
from vcs_scanner.api.schema.finding_status import FindingStatus

# First Party
from vcs_scanner.helpers.providers.rule_tag import RuleTagProvider
from vcs_scanner.post_processing.post_processor import PostProcessor


def test_write_correct_repository():
    toml_rule_path = Path(__file__).parent.parent.parent / "fixtures/rules.toml"
    rule_tag_provider = RuleTagProvider()
    rule_tag_provider.load(toml_rule_path)
    post_processor = PostProcessor(rule_tag_provider=rule_tag_provider)

    findings_to_process = []
    for i in range(1, 5):
        findings_to_process.append(
            Finding(
                file_path=f"file_path_{i}",
                column_start=i,
                column_end=i,
                line_number=i,
                commit_id=f"commit_{i}",
                commit_message=f"message_{i}",
                commit_timestamp=datetime.now(UTC),
                author=f"author_{i}",
                email=f"email_{i}",
                status=FindingStatus.NOT_ANALYZED,
                comment=f"comment_{i}",
                event_sent_on=datetime.now(UTC),
                rule_name=f"rule_{i}",
            )
        )
    findings_result = post_processor.run(findings_to_process)
    assert findings_result == findings_to_process
