# Third Party
import tomlkit
from resc_backend.resc_web_service.schema.finding import FindingCreate


def should_process_finding(
    finding: FindingCreate,
    rule_tags: dict = None,
    include_tags: [str] = None,
    ignore_tags: [str] = None,
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


def get_rule_tags(toml_rule_file_path: str) -> dict:
    """
        Get the tags per rule from the .toml rule file, from self.toml_rule_file_path
    :return: dict.
        The output will contain a dictionary with the rule id as the key and the tags as a list in the value
    """
    rule_tags = {}
    # read toml
    with open(toml_rule_file_path, encoding="utf-8") as toml_rule_file:
        toml_rule_dictionary = tomlkit.loads(toml_rule_file.read())
        # convert to dict
        for toml_rule in toml_rule_dictionary["rules"]:
            rule_id = toml_rule.get("id", None)
            if rule_id:
                rule_tags[rule_id] = toml_rule.get("tags", [])
    return rule_tags


def get_rule_comment(toml_rule_file_path: str) -> dict:
    """
        Get the tags per rule from the .toml rule file, from self.toml_rule_file_path
    :return: dict.
        The output will contain a dictionary with the rule id as the key and the tags as a list in the value
    """
    rule_comments = {}
    # read toml
    with open(toml_rule_file_path, encoding="utf-8") as toml_rule_file:
        toml_rule_dictionary = tomlkit.loads(toml_rule_file.read())
        # convert to dict
        for toml_rule in toml_rule_dictionary["rules"]:
            rule_id = toml_rule.get("id", None)
            if rule_id:
                rule_comments[rule_id] = toml_rule.get("comment", "")
    return rule_comments
