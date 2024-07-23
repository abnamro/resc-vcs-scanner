# Standard Library
import json
import logging
from json import JSONDecodeError

# Third Party
from pydantic import ValidationError

# First Party
from vcs_scanner.model import VCSInstanceRuntime

logger = logging.getLogger(__name__)


def _parse_vcs_instances_contents(contents: str, vcs_instances: list[VCSInstanceRuntime]) -> bool:
    parsed_vcs_instances = json.loads(contents)
    for vcs_instance in parsed_vcs_instances:
        try:
            logging.info(f"Parsing VCS instance '{vcs_instance}'")
            vcs_instances.append(VCSInstanceRuntime(**parsed_vcs_instances[vcs_instance]))
        except ValidationError as validation_error:
            logger.error(f"Failed while parsing VCS instance '{vcs_instance}': {validation_error}")
            return True
    return False


def parse_vcs_instances_file(filepath: str) -> list[VCSInstanceRuntime]:
    vcs_instances: list[VCSInstanceRuntime] = []
    errors_found = False
    logging.info(f"Reading VCS instances from file {filepath}")
    try:
        with open(filepath, encoding="utf-8") as vcs_instances_file:
            logging.info(f"Parsing VCS instance definitions from file {filepath}")
            errors_found = _parse_vcs_instances_contents(vcs_instances_file.read(), vcs_instances)

    except JSONDecodeError as json_error:
        logger.error(f"Failed to parse VCS instances file '{filepath}': {json_error}")
        errors_found = True
    except FileNotFoundError:
        logger.error(f"VCS Instances file not found: '{filepath}'")
        errors_found = True
    if errors_found:
        return []
    return vcs_instances
