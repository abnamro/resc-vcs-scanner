# Standard Library
import logging
import sys
from datetime import datetime
from typing import List, Optional

# Third Party
from prettytable import PrettyTable
from resc_backend.resc_web_service.schema.finding import FindingCreate
from resc_backend.resc_web_service.schema.repository import Repository
from resc_backend.resc_web_service.schema.scan import ScanRead
from resc_backend.resc_web_service.schema.scan_type import ScanType
from resc_backend.resc_web_service.schema.vcs_instance import VCSInstanceRead
from termcolor import colored

# First Party
from vcs_scanner.helpers.finding_action import FindingAction
from vcs_scanner.helpers.finding_filter import get_rule_comment, get_rule_tags, should_process_finding
from vcs_scanner.helpers.ignore_list_provider import IgnoredListProvider
from vcs_scanner.model import VCSInstanceRuntime
from vcs_scanner.output_modules.output_module import OutputModule

logger = logging.getLogger(__name__)


class STDOUTWriter(OutputModule):

    def __init__(self,
                 exit_code_warn: int,
                 exit_code_block: int,
                 toml_rule_file_path: str = None,
                 include_tags: List[str] = None,
                 ignore_tags: List[str] = None,
                 working_dir: str = "",
                 ignore_findings_path: str = "",
                 ):
        self.toml_rule_file_path: str = toml_rule_file_path
        self.exit_code_warn: int = exit_code_warn
        self.exit_code_block: int = exit_code_block
        self.include_tags: [str] = include_tags
        self.ignore_tags: [str] = ignore_tags
        self.exit_code_success = 0
        self.working_dir = working_dir
        self.ignore_findings_providers: IgnoredListProvider = IgnoredListProvider(ignore_findings_path)

    def write_vcs_instance(self,
                           vcs_instance_runtime: VCSInstanceRuntime) -> Optional[VCSInstanceRead]:
        vcs_instance = VCSInstanceRead(id_=1,
                                       name=vcs_instance_runtime.name,
                                       provider_type=vcs_instance_runtime.provider_type,
                                       hostname=vcs_instance_runtime.hostname,
                                       port=vcs_instance_runtime.port,
                                       scheme=vcs_instance_runtime.scheme,
                                       exceptions=vcs_instance_runtime.exceptions,
                                       scope=vcs_instance_runtime.scope,
                                       organization=vcs_instance_runtime.organization)
        logger.info(f"Scanning vcs instance {vcs_instance.name}")
        return vcs_instance

    def write_repository(self, repository: Repository) -> Repository:
        logger.info(f"Scanning repository {repository.project_key}/{repository.repository_name}")
        return repository

    @staticmethod
    def _determine_finding_action(finding: FindingCreate, rule_tags: dict = None) -> FindingAction:
        """
            Determine the action to take for the finding, based on the rule tags
        :param finding:
            FindingCreate instance of the finding
        :param rule_tags:
            Dictionary containing all the rules and there respective tags
        :return: FindingAction.
            FindingAction to take for this finding
        """
        rule_action = FindingAction.INFO
        if rule_tags and FindingAction.WARN in rule_tags.get(finding.rule_name, []):
            rule_action = FindingAction.WARN
        if rule_tags and FindingAction.BLOCK in rule_tags.get(finding.rule_name, []):
            rule_action = FindingAction.BLOCK

        return rule_action

    @staticmethod
    def _determine_if_ignored(rule_action: FindingAction,
                              finding: FindingCreate,
                              ignore_dictionary: dict,
                              working_dir: str) -> FindingAction:
        """
            Determine whether to ignore a blocker or not.
        :param rule_action:
            FindingAction containing the decision depending of rules.
        :param finding:
            FindingCreate instance of the finding
        :param ignore_dictionary:
            Dictionary containing all the list of ignored blockers
        :return: FindingAction.
            FindingAction to take for this finding
        """
        if rule_action is not FindingAction.BLOCK:
            logger.info(f"{rule_action}: {finding.file_path}")
            return rule_action

        if working_dir is None or working_dir == "":
            working_dir = "/"

        working_dir = str(working_dir)
        if working_dir[-1] != "/":
            working_dir = working_dir + "/"

        path_length: int = len(working_dir)
        finding_path: str = str(finding.file_path)
        if finding_path[:path_length] == working_dir:
            finding_path = finding_path[path_length:]

        key: str = finding_path + "|" + finding.rule_name + "|" + str(finding.line_number)
        if key in ignore_dictionary:
            return FindingAction.IGNORED

        return rule_action

    def write_findings(self, scan_id: int, repository_id: int, scan_findings: List[FindingCreate]):
        """
            Write the findings to the STDOUT in a nice table and set the exit code based on the FindingActions found
        :param scan_id:
            id of the scan in question
        :param repository_id:
            id of the repository in question
        :param scan_findings:
            List of FindingCreate of all the findings from the scan
        """
        # Initialize table
        output_table = PrettyTable()
        output_table.field_names = ['Level', 'Rule', 'Line', 'Position', 'File path', 'Comment']
        output_table.align = 'l'
        output_table.align['Line'] = 'r'

        block_count = 0
        warn_count = 0
        info_count = 0

        exit_code = self.exit_code_success
        rule_tags = get_rule_tags(self.toml_rule_file_path) if self.toml_rule_file_path else None
        rule_comments = get_rule_comment(self.toml_rule_file_path) if self.toml_rule_file_path else None
        ignore_dictionary = self.ignore_findings_providers.get_ignore_list()
        for finding in scan_findings:
            should_process = should_process_finding(finding=finding, rule_tags=rule_tags,
                                                    include_tags=self.include_tags, ignore_tags=self.ignore_tags)
            if should_process:
                finding_action = self._determine_finding_action(finding, rule_tags)
                finding_action = self._determine_if_ignored(finding_action,
                                                            finding,
                                                            ignore_dictionary,
                                                            self.working_dir)

                if finding_action == FindingAction.BLOCK:
                    finding_action_value = colored(finding_action.value, "red", attrs=["bold"])
                    block_count += 1
                elif finding_action in [FindingAction.WARN, FindingAction.IGNORED]:
                    finding_action_value = colored(finding_action.value, "light_red", attrs=["bold"])
                    warn_count += 1
                elif finding_action == FindingAction.INFO:
                    finding_action_value = colored(finding_action.value, "light_yellow", attrs=["bold"])
                    info_count += 1
                else:
                    finding_action_value = finding_action.value
                    info_count += 1

                if exit_code != self.exit_code_block:
                    if exit_code == self.exit_code_success and \
                       finding_action in [FindingAction.WARN, FindingAction.IGNORED]:
                        exit_code = self.exit_code_warn
                    elif finding_action == FindingAction.BLOCK:
                        exit_code = self.exit_code_block

                comment = rule_comments.get(finding.rule_name, "") if rule_comments else ""

                output_table.add_row([finding_action_value, finding.rule_name, finding.line_number,
                                     f"{finding.column_start}-{finding.column_end}", finding.file_path, comment])

        logger.info(f"\n{output_table.get_string(sortby='Level')}")

        logger.info(f"Findings detected : Total - {block_count+warn_count+info_count}, Block - {block_count}, "
                    f"Warn - {warn_count}, Info - {info_count}")

        if exit_code == self.exit_code_success:
            logger.info(f"Findings threshold check results: {colored('PASS', 'light_green', attrs=['bold'])}")
        elif exit_code == self.exit_code_block:
            logger.info(f"Findings threshold check results: {colored('FAIL', 'red', attrs=['bold'])}")
            logger.info(
                colored(f"Scan failed due to policy violations: [Block:{block_count}]", "red", attrs=["bold"]))
        elif exit_code == self.exit_code_warn:
            logger.info(f"Findings threshold check results: {colored('PASS', 'light_green', attrs=['bold'])}")
            logger.info(colored(f"Warning for policy violations: [Warn:{warn_count}]", "light_red", attrs=["bold"]))

        sys.exit(exit_code)

    def write_scan(self, scan_type_to_run: ScanType, last_scanned_commit: str, scan_timestamp: datetime,
                   repository: Repository, rule_pack: str) -> Optional[ScanRead]:
        logger.info(f"Running {scan_type_to_run} scan on repository {repository.repository_url}")
        return ScanRead(last_scanned_commit="NONE",
                        timestamp=datetime.now(),
                        repository_id=1,
                        id_=1,
                        rule_pack=rule_pack)

    def get_last_scan_for_repository(self, repository: Repository) -> ScanRead:
        return None
