import tomlkit


class RuleTagProvider:
    def __init__(self):
        self.toml_rule_file_path: str | None = None
        self.rule_tags: dict[str, list[str]] = {}

    def load(self, toml_rule_file_path: str) -> None:
        """
        Load a rule file into the provider.

        Args:
            toml_rule_file_path (str): path to the rule file.
        """
        self.toml_rule_file_path = toml_rule_file_path
        self.rule_tags = {}

    def get_rule_tags(self) -> dict[str, list[str]]:
        """
            Get the tags per rule from the .toml rule file, from self.toml_rule_file_path
        :return: dict.
            The output will contain a dictionary with the rule id as the key and the tags as a list in the value
        """
        if self.toml_rule_file_path is None:
            return {}

        if not self.rule_tags == {}:
            return self.rule_tags

        self.rule_tags = {}
        # read toml
        with open(self.toml_rule_file_path, encoding="utf-8") as toml_rule_file:
            toml_rule_dictionary = tomlkit.loads(toml_rule_file.read())
            # convert to dict
            for toml_rule in toml_rule_dictionary["rules"]:
                rule_id = toml_rule.get("id", None)
                if rule_id:
                    self.rule_tags[rule_id] = toml_rule.get("tags", [])
        return self.rule_tags
