import tomlkit


class RuleCommentProvider:
    def __init__(self):
        self.toml_rule_file_path: str | None = None
        self.rule_comment: dict[str, str] = {}

    def load(self, toml_rule_file_path: str) -> None:
        """
        Load a rule file into the provider.

        Args:
            toml_rule_file_path (str): path to the rule file.
        """
        self.toml_rule_file_path = toml_rule_file_path
        self.rule_comment = {}

    def get_comment(self) -> dict[str, list[str]]:
        """
            Get the comment per rule from the .toml rule file, from self.toml_rule_file_path
        :return: dict.
            The output will contain a dictionary with the rule id as the key and the comment as a string in the value
        """
        if self.toml_rule_file_path is None:
            return {}

        if not self.rule_comment == {}:
            return self.rule_comment

        # read toml
        with open(self.toml_rule_file_path, encoding="utf-8") as toml_rule_file:
            toml_rule_dictionary = tomlkit.loads(toml_rule_file.read())
            # convert to dict
            for toml_rule in toml_rule_dictionary["rules"]:
                rule_id = toml_rule.get("id", None)
                if rule_id:
                    self.rule_comment[rule_id] = toml_rule.get("comment", "")
        return self.rule_comment
