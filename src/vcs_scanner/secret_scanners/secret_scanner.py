# pylint: disable=E1101
# Standard Library
import logging
import os
import shutil
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

# Third Party
from git import Commit
from resc_backend.resc_web_service.schema.finding import FindingBase
from resc_backend.resc_web_service.schema.repository import Repository, RepositoryBase
from resc_backend.resc_web_service.schema.scan import Scan, ScanRead
from resc_backend.resc_web_service.schema.scan_type import ScanType

# First Party
from vcs_scanner.helpers.providers.rule_file import RuleFileProvider
from vcs_scanner.output_modules.output_module import OutputModule
from vcs_scanner.resc_worker import RESCWorker
from vcs_scanner.secret_scanners.git_operation import clone_repository
from vcs_scanner.secret_scanners.gitleaks_wrapper import GitLeaksWrapper

# This is an arbitrary number to distinguish between no issues, an error and
# the situation in which leaks are found. Note that this number cannot be bigger than 255 (OS limitation)
LEAKS_FOUND_EXIT_CODE = 42
NO_LEAKS_FOUND_EXIT_CODE = 0

logger = logging.getLogger(__name__)


class SecretScanner(RESCWorker):  # pylint: disable=R0902
    def __init__(
        self,
        gitleaks_binary_path: str,
        gitleaks_rules_provider: RuleFileProvider,
        rule_pack_version: str,
        output_plugin: OutputModule,
        repository: Repository,
        username: str,
        personal_access_token: str,
        scan_tmp_directory: str = ".",
        local_path: str | None = None,
        force_base_scan: bool = False,
        latest_commit: str | None = None,
    ):
        self.rule_provider: RuleFileProvider | None = None
        self.gitleaks_rules_provider: RuleFileProvider = gitleaks_rules_provider
        self.gitleaks_binary_path: str = gitleaks_binary_path
        self.rule_pack_version: str = rule_pack_version
        self._output_module: OutputModule = output_plugin
        self._scan_tmp_directory: str = scan_tmp_directory
        self.repository: Repository = repository
        self.username: str = username
        self.personal_access_token: str = personal_access_token
        self.local_path = local_path
        self.force_base_scan = force_base_scan
        self.latest_commit = latest_commit
        self.head_commit: None | Commit = None

        self._as_dir: bool = False
        self._as_repo: bool = False
        self._created_repository: None | RepositoryBase = None
        self._last_scanned_commit: None | str = None
        self._scan_type_to_run: None | ScanType = None
        self._scan_timestamp_start: None | datetime = None
        self._created_scan: None | ScanRead = None
        self._repo_clone_path: None | str = None
        self._findings_from_repo: list[FindingBase] = []
        self._findings_from_dir: list[FindingBase] = []
        self._findings: list[FindingBase] = []

        if self.local_path:
            self.repo_display_name = self.local_path.replace(".", "_").replace("/", "_")
        else:
            self.repo_display_name = self.repository.repository_url

    def run_scan(self, as_dir: bool = False, as_repo: bool = False) -> None:
        """
        Run the scan steps by steps.

        Args:
            as_dir (bool, optional): whether we scan as directory. Defaults to False.
            as_repo (bool, optional): whether we scan as repository. Defaults to False.
        """
        self._as_dir = as_dir
        self._as_repo = as_repo

        pipes: list[Callable[[], bool]] = [
            self._is_valid,
            self._is_scan_needed_from_latest_commit,
            self._create_repository,
            self._fetch_last_scanned_commit,
            self._is_scan_needed,
            self._start_timer,
            self._create_scan,
            self._clone_repo,
            self._run_repo_scan,
            self._run_dir_scan,
            self._merge_findings,
            self._write_findings,
        ]

        try:
            for pipe in pipes:
                # If the pipe does not succeed we exit immediately.
                if not pipe():
                    return
        except BaseException:
            logger.error(f"An error occurred while scanning {self.repository.repository_name}")
        finally:
            self._cleaning_up()

    def _is_valid(self) -> bool:
        if not self._as_dir and not self._as_repo:
            logger.error("no scan type selected")
            return False
        return True

    def _is_scan_needed_from_latest_commit(self) -> bool:
        if self._as_repo and not self.latest_commit:
            # There is no latest commit for this repository, assuming that its empty
            logger.info(
                f"Skipping scanning of {self.repository.project_key}/{self.repository.repository_name} "
                f"there are no commits"
            )
            return False
        logger.info(
            f"Started task for scanning {self.repository.repository_name} using "
            f"rule pack version: {self.rule_pack_version}"
        )
        return True

    def _create_repository(self) -> bool:
        # Insert in to repository table
        self._created_repository = self._output_module.write_repository(self.repository)
        if not self._created_repository:
            logger.error(
                f"Error processing "
                f"{self.repository.repository_name}."
                f" Error details: unable to create repository: {self._created_repository}"
            )
            return False

        logger.info(f"Scanning repository {self.repository.project_key}/{self.repository.repository_name}")
        return True

    def _fetch_last_scanned_commit(self) -> True:
        # Get last scanned commit for the repository
        last_scan_for_repository = self._output_module.get_last_scan_for_repository(repository=self._created_repository)
        self._last_scanned_commit = last_scan_for_repository.last_scanned_commit if last_scan_for_repository else None
        self._scan_type_to_run = self._determine_scan_type(
            last_scan_for_repository=last_scan_for_repository,
        )
        return True

    def _determine_scan_type(self, last_scan_for_repository: Scan) -> ScanType | None:
        # Force base scan, or has no previous scan
        if self.force_base_scan or last_scan_for_repository is None:
            return ScanType.BASE
        # Has previous scan
        if last_scan_for_repository:
            # Rule-pack is different from previous scan
            if last_scan_for_repository.rule_pack != self.rule_pack_version:
                return ScanType.BASE
            # Last commit is different from previous scan
            if self.latest_commit and self.latest_commit != last_scan_for_repository.last_scanned_commit:
                return ScanType.INCREMENTAL
        # Skip scanning, no conditions match
        return None

    def _is_scan_needed(self) -> bool:
        if self._scan_type_to_run is None:
            logger.info(
                "Skipped scanning on repository: "
                f"{self.repository.project_key}/{self.repository.repository_name} no new commits found."
            )
            return False
        return True

    def _start_timer(self) -> True:
        self._scan_timestamp_start = datetime.now(UTC)
        return True

    def _create_scan(self) -> bool:
        self._created_scan = self._output_module.write_scan(
            self._scan_type_to_run,
            self.latest_commit,
            self._scan_timestamp_start.isoformat(),
            self._created_repository,
            rule_pack=self.rule_pack_version,
        )
        if not self._created_scan:
            logger.error(
                f"Error processing {self.repository.project_key}/{self.repository.repository_name} "
                f"Error details: unable to create scan object"
            )
            return False
        return True

    def _clone_repo(self) -> True:
        # Clone and run scan upon the repository
        if not self.local_path:
            self._repo_clone_path = f"{self._scan_tmp_directory}/{self.repository.repository_name}"
            self.head_commit = clone_repository(
                repository_url=self.repository.repository_url,
                repo_clone_path=self._repo_clone_path,
                username=self.username,
                personal_access_token=self.personal_access_token,
            )
        else:
            self._repo_clone_path = self.local_path
        return True

    def _run_repo_scan(self) -> True:
        if not self._as_repo:
            return True

        if self.gitleaks_rules_provider.scan_as_repo_rule_file_path is None:
            return True

        logger.info(
            f"Started task for scanning {self._repo_clone_path} using rule pack version: {self.rule_pack_version}"
        )
        scan_timestamp_start = datetime.now(UTC)
        self._findings_from_repo = self._scan_repo(self._scan_type_to_run, self._last_scanned_commit)
        scan_timestamp_end = datetime.now(UTC)
        logger.info(
            f"Running {self._scan_type_to_run} scan on repository "
            f"{self.repository.project_key}/{self.repository.repository_name}"
            f" took {scan_timestamp_end - scan_timestamp_start} ms."
        )
        return True

    def _scan_repo(self, scan_type_to_run: str, last_scanned_commit: str) -> list[FindingBase]:
        """
            Clone and scan the given repository
        :param scan_type_to_run:
            Type of scan to run (Base or Incremental)
        :param last_scanned_commit:
            Last scanned commit of the repository to scan
        :return: Success, output.
            If Success is False, the output will contain an error message.
            Otherwise, the output will contain a list of findings or an empty list if no issue was found
        """

        logger.debug(f"Started scanning {self.repo_display_name}")
        if not self.local_path:
            report_filepath = f"{self._scan_tmp_directory}/{self._repo_clone_path}_{str(uuid.uuid4().hex)}.json"
        else:
            report_filepath = f"{self.local_path}/{self.repo_display_name}_{str(uuid.uuid4().hex)}.json"
        try:
            if scan_type_to_run == ScanType.BASE:
                scan_from = None
            elif scan_type_to_run == ScanType.INCREMENTAL and last_scanned_commit:
                scan_from = last_scanned_commit
            else:
                scan_from = None

            gitleaks_command = GitLeaksWrapper(
                scan_from=scan_from,
                gitleaks_path=self.gitleaks_binary_path,
                repository_path=self._repo_clone_path,
                rules_filepath=self.gitleaks_rules_provider.scan_as_repo_rule_file_path,
                report_filepath=report_filepath,
            )

            before_scan = time.time()
            findings: list[FindingBase] = gitleaks_command.start_scan()
            after_scan = time.time()
            scan_duration = int(after_scan - before_scan)
            logger.info(f"scan of repository {self._repo_clone_path} took {scan_duration} seconds")
            return findings
        except BaseException as error:
            logger.error(
                f"An exception occurred while scanning repository {self.repository.repository_url} " f"error: {error}"
            )
            return []
        finally:
            # Make sure the tempfile and repo cloned path removed
            logger.debug(f"Cleaning up the temporary report: {report_filepath}")
            if os.path.exists(report_filepath):
                os.remove(report_filepath)

    def _run_dir_scan(self):
        if not self._as_dir:
            return True

        if self.gitleaks_rules_provider.scan_as_dir_rule_file_path is None:
            return True

        logger.info(
            f"Started task for scanning {self._repo_clone_path} using rule pack version: {self.rule_pack_version}"
        )

        scan_timestamp_start = datetime.now(UTC)
        self._findings_from_dir = self._scan_directory(self._repo_clone_path)
        scan_timestamp_end = datetime.now(UTC)
        logger.info(
            f"Running directory scan on {self._repo_clone_path}"
            f" took {scan_timestamp_end - scan_timestamp_start} ms."
        )
        return True

    def _scan_directory(self, directory_path: str) -> list[FindingBase] | None:
        """
            Scan the given directory
        :param directory_path:
            Directory path to be scanned
        :return: Optional[List[FindingBase]].
            The output will contain a list of findings or an empty list if no finding was found
        """
        logger.debug(f"Started scanning {self.repo_display_name}:{directory_path}")
        if not self.local_path:
            report_filepath = f"{self._scan_tmp_directory}/{directory_path}_{str(uuid.uuid4().hex)}.json"
        else:
            report_filepath = f"{self.local_path}/{self.repo_display_name}_{str(uuid.uuid4().hex)}.json"
        try:
            gitleaks_command = GitLeaksWrapper(
                scan_from=None,
                gitleaks_path=self.gitleaks_binary_path,
                repository_path=directory_path,
                rules_filepath=self.gitleaks_rules_provider.scan_as_dir_rule_file_path,
                report_filepath=report_filepath,
                git_scan=False,
            )

            before_scan = time.time()
            findings: list[FindingBase] = gitleaks_command.start_scan()
            after_scan = time.time()
            scan_duration = int(after_scan - before_scan)
            logger.info(f"scan of repository {directory_path} took {scan_duration} seconds")
            return findings
        except BaseException as error:
            logger.error(f"An exception occurred while scanning directory {directory_path} error: {error}")
        finally:
            # Make sure the tempfile is removed
            logger.debug(f"Cleaning up the temporary report: {report_filepath}")
            if os.path.exists(report_filepath):
                os.remove(report_filepath)
        return None

    def _merge_findings(self) -> bool:
        if len(self._findings_from_dir) == 0 and len(self._findings_from_repo) == 0:
            path = (
                self.local_path
                if self.local_path
                else self.repository.project_key + "/" + self.repository.repository_name
            )
            logger.info(f"No findings registered in {path}.")
            return False

        self._findings = self._findings_from_repo + self._findings_from_dir
        self._findings = list(map(self._populate_if_empty, self._findings))
        return True

    def _populate_if_empty(self, finding: FindingBase) -> FindingBase:
        finding.commit_id = finding.commit_id or (
            self.head_commit.hexsha if self.head_commit is not None else "unknown"
        )
        finding.commit_message = finding.commit_message or (
            self.head_commit.message if self.head_commit is not None else ""
        )
        finding.commit_timestamp = finding.commit_timestamp or (
            self.head_commit.committed_date if self.head_commit is not None else datetime.now(UTC)
        )
        finding.author = finding.author or "vcs-scanner"
        return finding

    def _write_findings(self) -> True:
        logger.info(f"Scan completed: {len(self._findings)} findings were found.")
        self._output_module.write_findings(
            repository_id=getattr(self._created_repository, "id_", 0),
            scan_id=getattr(self._created_scan, "id_", 0),
            scan_findings=self._findings,
            repository_name=self.repository.repository_name,
        )
        return True

    def _cleaning_up(self) -> True:
        # Make sure the tempfile and repo cloned path removed
        logger.info(f"Cleaning up: {self._repo_clone_path}")
        if self._repo_clone_path and not os.path.exists(self._repo_clone_path):
            logger.error(f"path {self._repo_clone_path} does not exists")
        if self._repo_clone_path and not self.local_path and os.path.exists(self._repo_clone_path):
            logger.debug(f"Cleaning up the repository cloned directory: {self._repo_clone_path}")
            try:
                shutil.rmtree(self._repo_clone_path)
            except BaseException:
                logger.error(f"Failed to remove the repository cloned directory: {self._repo_clone_path}")
        return True
