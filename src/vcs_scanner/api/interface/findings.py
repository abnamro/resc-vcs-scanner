# Standard Library
import json
import logging

# Third Party
import requests

# First Party
from vcs_scanner.api.constants import (
    RWS_ROUTE_FINDINGS,
    RWS_ROUTE_SCANS,
    RWS_VERSION_PREFIX,
)
from vcs_scanner.api.schema.finding import FindingCreate

logger = logging.getLogger(__name__)


def create_findings(url: str, findings: list[FindingCreate]) -> requests.Response:
    api_url = f"{url}{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}"

    findings_json = []
    for finding in findings:
        findings_json.append(json.loads(finding.model_dump_json()))

    response = requests.post(api_url, json=findings_json, proxies={"http": "", "https": ""}, timeout=10)
    return response


def create_findings_with_scan_id(url: str, findings: list[FindingCreate], scan_id: int) -> requests.Response:
    api_url = f"{url}{RWS_VERSION_PREFIX}{RWS_ROUTE_SCANS}/{scan_id}{RWS_ROUTE_FINDINGS}"

    findings_json = []
    for finding in findings:
        findings_json.append(json.loads(finding.model_dump_json()))

    response = requests.post(api_url, json=findings_json, proxies={"http": "", "https": ""}, timeout=10)
    return response
