# pylint: disable=W0212
# Standard Library
import json
import logging
import sys
from argparse import Namespace
from datetime import datetime
from pathlib import Path

# Third Party
from resc_backend.constants import TEMP_RULE_FILE
from resc_backend.resc_web_service.schema.finding import FindingBase, FindingCreate
from resc_backend.resc_web_service.schema.repository import (
    RepositoryCreate,
    RepositoryRead,
)
from resc_backend.resc_web_service.schema.scan import Scan, ScanCreate, ScanRead
from resc_backend.resc_web_service.schema.scan_type import ScanType
from resc_backend.resc_web_service.schema.vcs_instance import (
    VCSInstanceCreate,
    VCSInstanceRead,
)
from resc_backend.resc_web_service_interface.findings import (
    create_findings_with_scan_id,
)
from resc_backend.resc_web_service_interface.repositories import (
    create_repository,
    get_last_scan_for_repository,
)
from resc_backend.resc_web_service_interface.rule_packs import (
    download_rule_pack_toml_file,
    get_rule_packs,
)
from resc_backend.resc_web_service_interface.scans import create_scan
from resc_backend.resc_web_service_interface.vcs_instances import create_vcs_instance
from tenacity import retry, stop_after_attempt, wait_exponential

# First Party
from vcs_scanner.common import get_rule_pack_version_from_file
from vcs_scanner.helpers.finding_filter import should_process_finding
from vcs_scanner.helpers.providers.rule_tag import RuleTagProvider
from vcs_scanner.model import VCSInstanceRuntime
from vcs_scanner.output_modules.output_module import OutputModule

logger = logging.getLogger(__name__)


class RESTAPIWriter(OutputModule):
    def __init__(
        self,
        rws_url,
        ignore_tags: list[str] = None,
        include_tags: list[str] = None,
        rule_tag_provider: RuleTagProvider = RuleTagProvider(),
    ):
        self.rws_url = rws_url
        self.ignore_tags = ignore_tags
        self.include_tags = include_tags
        self.rule_tag_provider: RuleTagProvider = rule_tag_provider

    def load_rules(self, toml_rule_file_path: str) -> None:
        self.rule_tag_provider.load(toml_rule_file_path)

    def write_vcs_instance(self, vcs_instance_runtime: VCSInstanceRuntime) -> VCSInstanceRead | None:
        created_vcs_instance = None
        vcs_instance = VCSInstanceCreate(
            name=vcs_instance_runtime.name,
            provider_type=vcs_instance_runtime.provider_type,
            hostname=vcs_instance_runtime.hostname,
            port=vcs_instance_runtime.port,
            scheme=vcs_instance_runtime.scheme,
            exceptions=vcs_instance_runtime.exceptions,
            scope=vcs_instance_runtime.scope,
            organization=vcs_instance_runtime.organization,
        )
        response = create_vcs_instance(self.rws_url, vcs_instance)
        if response.status_code == 201:
            created_vcs_instance = VCSInstanceRead(**json.loads(response.text))
        else:
            logger.warning(f"Creating vcs_instance failed with error: {response.status_code}->{response.text}")
        return created_vcs_instance

    def write_repository(self, repository: RepositoryCreate) -> RepositoryRead | None:
        created_repository = None
        response = create_repository(self.rws_url, repository)
        if response.status_code == 201:
            created_repository = RepositoryRead(**json.loads(response.text))
        else:
            logger.warning(f"Creating repository failed with error: {response.status_code}->{response.text}")
        return created_repository

    def write_findings(
        self,
        scan_id: int,
        repository_id: int,
        scan_findings: list[FindingBase],
        repository_name: str = "",
    ) -> None:
        findings_create = []

        rule_tags = self.rule_tag_provider.get_rule_tags()
        for finding in scan_findings:
            # We strip the repository name here because in the case of
            # scan as dir the path of the finding is prefixed with the repository name
            if finding.author == "vcs-scanner":
                finding.file_path = finding.file_path.removeprefix(repository_name + "/")

            new_finding = FindingCreate.create_from_base_class(base_object=finding, repository_id=repository_id)

            if should_process_finding(
                finding=finding,
                rule_tags=rule_tags,
                ignore_tags=self.ignore_tags,
                include_tags=self.include_tags,
            ):
                findings_create.append(new_finding)

        response = create_findings_with_scan_id(self.rws_url, findings_create, scan_id)

        if response.status_code != 201:
            logger.warning(
                f"Creating findings for scan {scan_id} " f"failed with error: {response.status_code}->{response.text}"
            )
        logger.info(f"Found {len(scan_findings)} issues during scan for scan_id: {scan_id} ")

    def write_scan(
        self,
        scan_type_to_run: ScanType,
        last_scanned_commit: str,
        scan_timestamp: datetime,
        repository: RepositoryRead,
        rule_pack: str,
    ) -> ScanRead | None:
        created_scan = None
        scan_object = ScanCreate.create_from_base_class(
            base_object=Scan(
                scan_type=scan_type_to_run,
                last_scanned_commit=last_scanned_commit,
                timestamp=scan_timestamp,
                rule_pack=rule_pack,
            ),
            repository_id=repository.id_,
        )

        response = create_scan(self.rws_url, scan_object)
        if response.status_code == 201:
            created_scan = ScanRead(**json.loads(response.text))
            logger.info(f"Successfully created scan for repository {repository.repository_url} ")
        else:
            logger.warning(
                f"Creating {scan_type_to_run} scan failed with error: {response.status_code}->{response.text}"
            )

        return created_scan

    def get_last_scan_for_repository(self, repository: RepositoryRead) -> ScanRead | None:
        response = get_last_scan_for_repository(self.rws_url, repository.id_)
        if not response.status_code == 200:
            logger.warning(f"Retrieving last scan details failed with error: {response.status_code}->{response.text}")
            return None

        if not response.text or response.text == "null":
            return None
        return ScanRead(**json.loads(response.text))

    @retry(wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(100))
    def write_vcs_instances(self, vcs_instances_dict: dict[str, VCSInstanceRuntime]) -> dict[str, VCSInstanceRuntime]:
        try:
            for key in vcs_instances_dict:
                vcs_instance = vcs_instances_dict[key]
                vcs_instance_created = self.write_vcs_instance(vcs_instance)
                if not vcs_instance_created:
                    raise ValueError(f"Failed creating vcs instance {vcs_instance.name}")
                vcs_instance.id_ = vcs_instance_created.id_
                vcs_instances_dict[key] = vcs_instance
            return vcs_instances_dict
        except ValueError as ex:
            logger.error(f"Failed creating vcs instances, is the API available? | {ex} | Retrying...")
            raise

    def get_active_rule_pack_version(self) -> str | None:
        """
            Retrieve active rule pack version from database
        :return: str
            Return active rule pack version
        """
        active_rule_pack_version = None
        response = get_rule_packs(url=self.rws_url, active=True)
        if response.status_code == 200:
            json_body = json.loads(response.text)
            active_rule_pack_version = json_body["data"][0]["version"] if json_body else None
        else:
            logger.warning(
                f"Retrieving active rule pack version failed with error: {response.status_code}->{response.text}"
            )
        return active_rule_pack_version

    def download_rule_pack(self, rule_pack_version: str | None = "") -> str | None:
        """
            Download rule pack
        :param rule_pack_version:
            optional, filter on rule pack version
        :return: str
            Return downloaded rule pack version
        """
        response = download_rule_pack_toml_file(self.rws_url, rule_pack_version)
        if not response.status_code == 200:
            logger.error(
                f"Aborting scan! Downloading rule pack version {rule_pack_version} failed with "
                f"error: {response.status_code}->{response.text}"
            )
            sys.exit(-1)

        filename = Path(TEMP_RULE_FILE)
        filename.write_bytes(response.content)
        if rule_pack_version:
            logger.debug(
                f"Rule pack version: {rule_pack_version} has been successfully "
                f"downloaded to location {TEMP_RULE_FILE}"
            )
        else:
            rule_pack_version = get_rule_pack_version_from_file(response.content)
            if not rule_pack_version:
                logger.warning("Unable to obtain the rule pack version from downloaded file, defaulting to '0.0.0'")
            logger.debug(
                f"Latest rule pack version: {rule_pack_version} has been successfully "
                f"downloaded to location {TEMP_RULE_FILE}"
            )
        return rule_pack_version

    def check_active_rule_pack_version(self, rule_pack_version: str = None) -> str:
        """
            Check active rule pack version
        :return: str
            Return active rule pack version
        """
        if rule_pack_version:
            rule_pack_version_from_db = self.get_active_rule_pack_version()

            if rule_pack_version != rule_pack_version_from_db:
                rule_pack_version = self.download_rule_pack(rule_pack_version_from_db)
        else:
            rule_pack_version = self.download_rule_pack()
        return rule_pack_version

    @staticmethod
    def make(args: Namespace) -> "RESTAPIWriter":
        """
            Get the Rest API writer given the args provided.

        :param args:
            Namespace object containing the CLI arguments
        """
        rule_tag_provider = RuleTagProvider()
        rule_tag_provider.load(args.gitleaks_rules_path)

        output_plugin = RESTAPIWriter(
            rws_url=args.rws_url,
            include_tags=args.include_tags,
            ignore_tags=args.ignore_tags,
            rule_tag_provider=rule_tag_provider,
        )
        return output_plugin
