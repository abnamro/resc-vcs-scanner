# Third Party
from resc_backend.resc_web_service.schema.finding import FindingCreate


def should_process_finding(
    finding: FindingCreate,
    rule_tags: dict = None,
    include_tags: list[str] = None,
    ignore_tags: list[str] = None,
) -> bool:
    """
        Determine the action to take for the finding, based on the rule tags
    :param finding:
        FindingCreate instance of the finding
    :param rule_tags:
        Dictionary containing all the rules and there respective tags
    :param include_tags:
        include_tags will check for the tag
    :param ignore_tags:
        include_tags will check for the tag
    :return bool:
        The output will be boolean, based on the tag filter given
    """
    # Rule tag is not in the include tags list, return false
    if include_tags and rule_tags and set(include_tags).isdisjoint(set(rule_tags.get(finding.rule_name, []))):
        return False

    # Rule tag is in the ignore tags list, return false
    if ignore_tags and rule_tags and not set(ignore_tags).isdisjoint(set(rule_tags.get(finding.rule_name, []))):
        return False

    return True
