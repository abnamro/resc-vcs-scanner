# Third Party
import logging

import tomlkit
from resc_backend.constants import RULE_TAG_SCAN_AS_DIR

from vcs_scanner.helpers.gitleaks_types import GitLeaksConfigToml, RuleToml

logger = logging.getLogger(__name__)


class RuleFileProvider:
    def __init__(self, toml_rule_file_path: str, init: bool = False):
        self.base_rule_file_path: str = toml_rule_file_path
        self.scan_as_repo_rule_file_path: str | None = toml_rule_file_path if init else None
        self.scan_as_dir_rule_file_path: str | None = toml_rule_file_path if init else None

    def init(self, destination_rule_as_repo: str, destination_rule_as_dir: str) -> None:
        if destination_rule_as_repo == self.base_rule_file_path and destination_rule_as_dir == self.base_rule_file_path:
            self.scan_as_repo_rule_file_path = destination_rule_as_repo
            self.scan_as_dir_rule_file_path = destination_rule_as_dir
            return None

        if self.scan_as_dir_rule_file_path is not None or self.scan_as_repo_rule_file_path is not None:
            return None

        toml_dict: GitLeaksConfigToml = {}
        rules_as_repo: list[RuleToml] = []
        rules_as_dir: list[RuleToml] = []

        # read toml
        with open(self.base_rule_file_path, encoding="utf-8") as toml_rule_file:
            toml_rule_dictionary = tomlkit.load(toml_rule_file)
            toml_dict = toml_rule_dictionary.unwrap()
            for rule in toml_dict.get("rules", []):
                (rules_as_dir if RULE_TAG_SCAN_AS_DIR in rule.get("tags", []) else rules_as_repo).append(rule)

        if len(rules_as_repo) > 0:
            if self._create_rule_file(toml_dict, rules_as_repo, destination_rule_as_repo):
                self.scan_as_repo_rule_file_path = destination_rule_as_repo

        if len(rules_as_dir) > 0:
            if self._create_rule_file(toml_dict, rules_as_dir, destination_rule_as_dir):
                self.scan_as_dir_rule_file_path = destination_rule_as_dir

    def _create_rule_file(self, toml_dict: GitLeaksConfigToml, rules: list[RuleToml], destination: str) -> bool:
        """
        Create a rule file given toml dictionary

        Args:
            toml_dict (dict): _description_
            rules (list): _description_
            destination (str): _description_

        Returns:
            bool: True on successfully created file.
        """

        new_toml_dict: GitLeaksConfigToml = {
            "title": toml_dict["title"],
            "version": toml_dict["version"],
            "rules": rules,
            "allowlist": toml_dict.get("allowlist", []),
        }

        try:
            with open(destination, "w") as f:
                tomlkit.dump(new_toml_dict, f)
        except OSError as err:
            logger.error(f"could not write in {destination}: {err}")
        except Exception as err:
            logger.error(f"Unexpected {err=}, {type(err)=}")
            return False

        return True
