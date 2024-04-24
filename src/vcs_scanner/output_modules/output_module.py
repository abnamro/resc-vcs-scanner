# Standard Library
import abc
from typing import List, Optional

# Third Party
from resc_backend.resc_web_service.schema.finding import FindingCreate
from resc_backend.resc_web_service.schema.repository import Repository
from resc_backend.resc_web_service.schema.scan import Scan, ScanRead
from resc_backend.resc_web_service.schema.scan_type import ScanType
from resc_backend.resc_web_service.schema.vcs_instance import VCSInstanceRead

# First Party
from vcs_scanner.model import VCSInstanceRuntime


class OutputModule(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def write_vcs_instance(
        self, vcs_instance_runtime: VCSInstanceRuntime
    ) -> Optional[VCSInstanceRead]:
        raise NotImplementedError

    @abc.abstractmethod
    def write_repository(self, repository: Repository):
        raise NotImplementedError

    @abc.abstractmethod
    def write_findings(
        self,
        scan_id: int,
        repository_id: int,
        scan_findings: List[FindingCreate],
    ):
        raise NotImplementedError

    @abc.abstractmethod
    def write_scan(
        self,
        scan_type_to_run: ScanType,
        last_scanned_commit: str,
        scan_timestamp: str,
        repository: Repository,
        rule_pack: str,
    ) -> Scan:
        raise NotImplementedError

    @abc.abstractmethod
    def get_last_scan_for_repository(self, repository: Repository) -> ScanRead:
        raise NotImplementedError
