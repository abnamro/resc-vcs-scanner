# pylint: disable=bad-option-value,C0413
# Standard Library
import logging
import os

os.environ["GIT_PYTHON_REFRESH"] = "quiet"

# Third Party
from git import Commit, Repo  # noqa: E402

logger = logging.getLogger(__name__)


def clone_repository(
    repository_url: str,
    repo_clone_path: str,
    username: str = "",
    personal_access_token: str = "",
) -> Commit:
    """
        Clones the given repository
    :param repository_url:
        Repository url to clone
    :param repo_clone_path:
        Path where to clone the repository
    :param username:
        Username to clone the repository, only needed if the repository is private
    :param personal_access_token:
        Personal access token|password to clone the repository, only needed if the repository is private
    """
    url = repository_url.replace("https://", "")
    repo_clone_url = f"https://{username}:{personal_access_token}@{url}"
    repo = Repo.clone_from(repo_clone_url, repo_clone_path)
    logger.debug(f"Repository {repository_url} cloned successfully")
    logger.info(f"Repository cloned to {repo_clone_path}")
    return repo.head.commit


def read_repo_from_local(path_to_dir: str) -> str:
    """Given a path returns the remote address of the repository

    Args:
        path_to_dir (str): Path to the repo (.git must be in that directory)

    Returns:
        str: Url of the repository
    """
    repo = Repo(path_to_dir)
    logger.debug(repo.remotes[0].url)
    return repo.remotes[0].url
