import pathlib
from argparse import ArgumentParser

from vcs_scanner.helpers.env_default import EnvDefault


def create_cli_argparser() -> ArgumentParser:
    """
        Create ArgumentParser for CLI arguments
    :return: ArgumentParser.
        ArgumentParser instance with all arguments as expected for RESC
    """
    parser_common = ArgumentParser(add_help=False)
    parser_common.add_argument(
        "--gitleaks-path",
        type=pathlib.Path,
        action=EnvDefault,
        envvar="RESC_GITLEAKS_PATH",
        required=True,
        help="Path to the gitleaks binary. " "Can also be set via the RESC_GITLEAKS_PATH environment variable",
    )
    parser_common.add_argument(
        "--gitleaks-rules-path",
        type=pathlib.Path,
        action=EnvDefault,
        required=True,
        envvar="RESC_GITLEAKS_RULES_PATH",
        help="Path to the gitleaks rules file. "
        "Can also be set via the "
        "RESC_GITLEAKS_RULES_PATH environment variable",
    )
    parser_common.add_argument(
        "--ignored-blocker-path",
        type=pathlib.Path,
        action=EnvDefault,
        required=False,
        envvar="RESC_IGNORED_BLOCKER_PATH",
        help="Path to the resc-ignore.dsv file. "
        "Can also be set via the "
        "RESC_IGNORED_BLOCKER_PATH "
        "environment variable",
    )
    parser_common.add_argument(
        "-w",
        "--exit-code-warn",
        required=False,
        action=EnvDefault,
        default=2,
        type=int,
        envvar="RESC_EXIT_CODE_WARN",
        help="Exit code given if CLI encounters findings tagged with Warn, default 2. "
        "Can also be set via the RESC_EXIT_CODE_WARN environment variable",
    )
    parser_common.add_argument(
        "-b",
        "--exit-code-block",
        required=False,
        action=EnvDefault,
        default=1,
        type=int,
        envvar="RESC_EXIT_CODE_BLOCK",
        help="Exit code given if CLI encounters findings tagged with Block, default 1. "
        "Can also be set via the RESC_EXIT_CODE_BLOCK environment variable",
    )
    parser_common.add_argument(
        "--include-tags",
        required=False,
        action=EnvDefault,
        type=str,
        envvar="RESC_INCLUDE_TAGS",
        help="Filter for outputting findings based on specified tags. "
        "Provided as comma separated list. "
        "Can also be set via the RESC_INCLUDE_TAGS environment variable",
    )
    parser_common.add_argument(
        "--ignore-tags",
        required=False,
        action=EnvDefault,
        type=str,
        envvar="RESC_IGNORE_TAGS",
        help="Filter for NOT outputting findings based on specified tags. "
        "Provided as comma separated list. "
        "Can also be set via the RESC_IGNORE_TAGS environment variable",
    )
    parser_common.add_argument(
        "-v",
        "--verbose",
        required=False,
        action="store_true",
        help="Enable more verbose logging",
    )

    repository_common = ArgumentParser(add_help=False)
    repository_common.add_argument(
        "--repo-name",
        type=str,
        required=False,
        action=EnvDefault,
        envvar="RESC_REPO_NAME",
        help="The name of the repository. " "Can also be set via the RESC_REPO_NAME environment variable",
    )
    repository_common.add_argument("--force-base-scan", required=False, action="store_true")

    repository_common.add_argument(
        "--rws-url",
        type=str,
        required=False,
        action=EnvDefault,
        envvar="RESC_RWS_URL",
        help="The URL to the secret tracking service to which the scan results should "
        "be written. "
        "Can also be set via the RESC_RWS_URL environment variable",
    )

    parser: ArgumentParser = ArgumentParser()

    subparser = parser.add_subparsers(title="command", dest="command", required=True, help="Options dir, repo")
    directory = subparser.add_parser(
        "dir",
        description="Scan a directory",
        help="Scan a directory",
        parents=[parser_common],
    )
    repository = subparser.add_parser("repo", description="Scan a Git repository", help="Scan a Git repository")

    directory.add_argument(
        "--dir",
        type=pathlib.Path,
        required=True,
        action=EnvDefault,
        envvar="RESC_SCAN_PATH",
        help="The path to the directory where the scan target. "
        "Can also be set via the RESC_SCAN_PATH environment variable",
    )

    repository_subparser = repository.add_subparsers(
        title="repository_location",
        dest="repository_location",
        required=True,
        help="Options local, remote",
    )
    repository_local = repository_subparser.add_parser(
        "local",
        description="Scan a locally already cloned repository",
        help="Scan a locally already cloned repository",
        parents=[parser_common, repository_common],
    )
    repository_remote = repository_subparser.add_parser(
        "remote",
        description="Scan a remote repository",
        help="Scan a remote repository",
        parents=[parser_common, repository_common],
    )

    repository_local.add_argument(
        "--dir",
        type=pathlib.Path,
        required=True,
        action=EnvDefault,
        envvar="RESC_SCAN_PATH",
        help="The path to the directory where the repo is located. "
        "Can also be set via the RESC_SCAN_PATH environment variable",
    )

    repository_remote.add_argument(
        "--repo-url",
        type=str,
        required=True,
        action=EnvDefault,
        envvar="RESC_REPO_URL",
        help="url to repository you want to scan. " "Can also be set via the RESC_REPO_URL environment variable",
    )
    repository_remote.add_argument(
        "--username",
        type=str,
        required=False,
        action=EnvDefault,
        envvar="RESC_REPO_USERNAME",
        help="The username used for cloning the repository, "
        "you will be prompted for the password. "
        "Can also be set via the RESC_REPO_USERNAME & RESC_REPO_PASSWORD environment "
        "variable",
    )

    return parser
