"""
GitLab entry point.

The GitLab and GitHub engines used to be two near-identical 450-line files that
drifted apart whenever a check was added to one and not the other. There is now
one engine in checks.py driven by a RepoClient, and this module is the thin
GitLab adapter that remains for callers that still import it by name.
"""
import logging

from app.checks import run_all_checks
from app.repo_client import GitlabRepoClient

logger = logging.getLogger(__name__)


def run_gitlab_checks(project_id: int, token: str, gitlab_url: str = 'https://gitlab.com',
                      verify_ssl: bool = True, custom_dns: str = '') -> list[dict]:
    logger.info('GitLab audit [project_id=%s]: starting checks', project_id)
    client = GitlabRepoClient(project_id, token, gitlab_url, verify_ssl, custom_dns).load()
    return run_all_checks(client)
