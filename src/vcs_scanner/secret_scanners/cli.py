# Standard Library
import getpass
import json
import logging.config
import os
from argparse import ArgumentParser, Namespace
from urllib.parse import urlparse

# Third Party
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders

# First Party
from vcs_scanner.common import get_rule_pack_version_from_file, initialise_logs
from vcs_scanner.constants import (
    CLI_VCS_AZURE,
    CLI_VCS_BITBUCKET,
    CLI_VCS_LOCAL_SCAN,
    LOG_FILE_PATH_CLI,
)
from vcs_scanner.helpers.cli import create_cli_argparser
from vcs_scanner.helpers.providers.rule_file import RuleFileProvider
from vcs_scanner.model import RepositoryRuntime
from vcs_scanner.output_modules.rws_api_writer import RESTAPIWriter
from vcs_scanner.output_modules.stdout_writer import STDOUTWriter
from vcs_scanner.secret_scanners.git_operation import read_repo_from_local
from vcs_scanner.secret_scanners.secret_scanner import SecretScanner

logger_config = initialise_logs(LOG_FILE_PATH_CLI)
logger = logging.getLogger(__name__)

FAKE_COMMIT = "hash"
FAKE_URL = "http://fake-host.none"


def deserialize_repository_from_file(filepath: str) -> RepositoryRuntime:
    with open(filepath, encoding="utf-8") as repo_file:
        repository_str: str = repo_file.read()
    repository: RepositoryRuntime = RepositoryRuntime(**json.loads(repository_str))
    return repository


def get_repository_name_from_url(repo_url: str) -> str:
    """
        Get repository name from given URL, taking the last segment of the url as name
    :param repo_url:
        Full url to the repository
    :return: str.
        The output will the name of the repository based on the url
    """
    url = urlparse(repo_url)
    if url.path.split("/")[-1] == "":
        return url.path.split("/")[-2]
    return url.path.split("/")[-1]


def validate_cli_arguments(args: Namespace):  # pylint: disable=R0912
    """
        Validate the CLI arguments given
    :param args:
        Namespace object containing the arguments parsed from the CLI
    :return: args or False.
        The output will be the args given, unless validation fails then it contains False
    """
    valid_arguments = True
    # Prompt for the password for a remote repo if username is specified
    if args.command == "repo" and args.repository_location == "remote" and args.username:
        if "RESC_REPO_PASSWORD" in os.environ:
            args.password = os.environ["RESC_REPO_PASSWORD"]
        else:
            args.password = getpass.getpass("Password:")

    # Derive the repository name from the directory or url if not provided
    if args.command == "repo" and args.repository_location == "remote" and not args.repo_name:
        args.repo_name = get_repository_name_from_url(args.repo_url)
    elif args.command == "dir" or (
        args.command == "repo" and args.repository_location == "local" and not args.repo_name
    ):
        if not os.path.isdir(args.dir.absolute()):
            logger.error(f"The directory {args.dir.absolute()} does not exist")
            valid_arguments = False
        args.repo_name = os.path.split(args.dir.absolute())[1]

    # Split the include_tags by comma if supplied
    args.include_tags = args.include_tags.split(",") if args.include_tags else None

    # Split the ignore_tags by comma if supplied
    args.ignore_tags = args.ignore_tags.split(",") if args.ignore_tags else None

    if not valid_arguments:
        return False

    return args


def scan_repository_from_cli():
    """
    Startup command for the CLI, parsing arguments and starting the process
    """
    parser: ArgumentParser = create_cli_argparser()
    args: Namespace = parser.parse_args()
    args = validate_cli_arguments(args)

    if args.verbose:
        logger_config.setLevel(logging.DEBUG)
    else:
        logger_config.setLevel(logging.INFO)

    if args.command == "dir":
        logger.info(f"Scanning directory {args.dir.absolute()}")
        scan_directory(args)
    elif args.command == "repo":
        if args.repository_location == "local":
            logger.info(f"Scanning repository local {args.dir.absolute()}")
            args.repo_url = fetch_url_from_dot_git_config(args.dir.absolute())
            args.username = None
            args.password = None
        elif args.repository_location == "remote":
            logger.info(f"Scanning repository remote {args.repo_url}")
        scan_repository(args)


def fetch_url_from_dot_git_config(path: str):
    if not os.path.exists(path / ".git/config"):
        return FAKE_URL

    return read_repo_from_local(path)


# TODO refactor and merge scan_directory / scan_repository to avoid code duplication.
def scan_directory(args: Namespace):
    """
        Start the process of scanning a non-git directory
    :param args:
        Namespace object containing the CLI arguments
    """
    repository = RepositoryRuntime(
        repository_url=FAKE_URL,
        repository_name="local",
        repository_id="local",
        project_key="local",
        vcs_instance_name="vcs_instance_name",
        latest_commit=FAKE_COMMIT,
    )

    output_plugin = STDOUTWriter.make(args)
    rule_pack_version = _get_rule_pack_version(args)

    if not rule_pack_version:
        rule_pack_version = "0.0.0"

    gitleaks_rules_provider = RuleFileProvider(args.gitleaks_rules_path, init=True)

    secret_scanner = SecretScanner(
        gitleaks_binary_path=args.gitleaks_path,
        gitleaks_rules_provider=gitleaks_rules_provider,
        rule_pack_version=rule_pack_version,
        output_plugin=output_plugin,
        repository=repository.convert_to_repository(vcs_instance_id=1),
        username="",
        personal_access_token="",
        local_path=f"{args.dir.absolute()}",
        # we force a base scan because it does not matter
        # in this use case: we are not sending data to RESC.
        force_base_scan=True,
    )

    secret_scanner.run_scan(as_dir=True)


def scan_repository(args: Namespace):
    """
        Start the process of scanning a git repository (remote or local)
    :param args:
        Namespace object containing the CLI arguments
    """
    vcs_type = guess_vcs_provider(args.repo_url)
    vcs_name = determine_vcs_name(args.repo_url, vcs_type)

    repository = RepositoryRuntime(
        repository_url=args.repo_url,
        repository_name=args.repo_name,
        repository_id=args.repo_name,
        project_key=args.repo_name,
        vcs_instance_name=vcs_name,
        latest_commit=FAKE_COMMIT,
    )

    if args.rws_url:
        output_plugin = RESTAPIWriter.make(args)
        rule_pack_version = output_plugin.download_rule_pack()

    else:
        output_plugin = STDOUTWriter.make(args)
        rule_pack_version = _get_rule_pack_version(args)

    if not rule_pack_version:
        rule_pack_version = "0.0.0"

    gitleaks_rules_provider = RuleFileProvider(args.gitleaks_rules_path, init=True)

    secret_scanner = SecretScanner(
        gitleaks_binary_path=args.gitleaks_path,
        gitleaks_rules_provider=gitleaks_rules_provider,
        rule_pack_version=rule_pack_version,
        output_plugin=output_plugin,
        repository=repository.convert_to_repository(vcs_instance_id=1),
        username=args.username,
        personal_access_token=args.password,
        local_path=f"{args.dir.absolute()}",
        force_base_scan=args.force_base_scan,
        latest_commit="unknown",
    )

    secret_scanner.run_scan(as_repo=True)


def guess_vcs_provider(repo_url: str) -> VCSProviders:
    """
        Guess the vcs provider based on the url given, defaulted to bitbucket
    :param repo_url:
        Full url of the repository
    :return: VCSProviders.
        The output will contain the guessed VCSProviders enum value
    """
    url = urlparse(repo_url)
    if "bitbucket" in url.netloc:
        return VCSProviders.BITBUCKET
    if "dev.azure" in url.netloc:
        return VCSProviders.AZURE_DEVOPS
    logger.warning("Unable to guess VCS_Provider, assuming it is bitbucket.")
    return VCSProviders.BITBUCKET


def determine_vcs_name(repo_url: str, vcs_type: VCSProviders) -> str:
    """
        Determine the vcs provider name based on the vcs_type given, defaulted to CLI_VCS_LOCAL_SCAN
    :param repo_url:
        Full url of the repository
    :param vcs_type:
        VCSProviders type of the repository
    :return: str.
        The output will contain the name of the vcs provider
    """
    vcs_name = CLI_VCS_LOCAL_SCAN
    if repo_url and repo_url is not FAKE_URL:
        if vcs_type == VCSProviders.AZURE_DEVOPS:
            vcs_name = CLI_VCS_AZURE
        elif vcs_type == VCSProviders.BITBUCKET:
            vcs_name = CLI_VCS_BITBUCKET
    return vcs_name


def _get_rule_pack_version(args: Namespace) -> str | None:
    with open(args.gitleaks_rules_path, encoding="utf-8") as rule_pack:
        return get_rule_pack_version_from_file(rule_pack.read())
