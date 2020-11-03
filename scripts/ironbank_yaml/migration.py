#!/usr/bin/env python3

import argparse
import sys
import tempfile
from pathlib import Path
import logging

import git
import generate
import gitlab

MR_DESCRIPTION = """Migrate to ironbank.yaml

Please review the contents of the new `ironbank.yaml` file.

* [ ] Add any additional internal or external maintainers to the
  `maintainers:` list.
* [ ] Add any required build args to the `args:` list.
* [ ] ...
"""

logger = logging.getLogger("ironbank_yaml.migration")


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument(
        "--dry-run",
        default=False,
        type=bool,
        help="Testing flag to dry run the script",
    )
    parser.add_argument(
        "--repo1-token",
        required=True,
        help="Personal access token for accessing gitlab",
    )
    parser.add_argument(
        "--repo1-url",
        default="https://repo1.dsop.io/",
        help="URL for Repo1",
    )
    parser.add_argument(
        "--start-branch",
        default="development",
        help="Branch to make MRs againt",
    )
    parser.add_argument(
        "--branch",
        default="ironbank-yaml-migration",
        help="New branch name for MR",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Log level",
        choices=("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"),
    )
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level, stream=sys.stdout)

    gl = gitlab.Gitlab(args.repo1_url, private_token=args.repo1_token)
    greylists = _list_greylists(args.repo1_url)
    for greylist in greylists:
        _process_greylist(greylist, gl, **vars(args))


def _process_greylist(
    greylist,
    gl,
    dry_run,
    repo1_url,
    start_branch,
    branch,
    dccscr_whitelists_branch="master",
    **kwargs,
):
    # Path to the greylist in the repo
    greylist_path = greylist.as_posix()
    # Everything but the final *.greylist filename is the project name
    project = "dsop/" + "/".join(greylist.parts[:-1])

    logger.info(f"Processing {project}")

    try:
        gl_project = gl.projects.get(project, lazy=True)
        branches = [b.name for b in gl_project.branches.list()]
    except gitlab.exceptions.GitlabListError:
        # Old greylists like dsop/opensource/foo/1.2.3/foo-1.2.3.greylist will result in an error that can be ignored
        logger.warning(f"Failed to get branches for {project}")
        return

    if start_branch not in branches:
        logger.error(f"{project} does not have {start_branch} branch")
        return

    if branch in branches:
        logger.info(f"{project} already has {branch} branch, skipping")
        return

    try:
        tree = [f["path"] for f in gl_project.repository_tree(ref=start_branch)]
    except gitlab.exceptions.GitlabError:
        logger.exception(f"Failed to list repository tree for {project}")
        return

    if "ironbank.yaml" in tree:
        logger.info(f"{project} already has ironbank.yaml, skipping")
        return

    try:
        yaml = generate.generate(
            greylist_path=greylist_path,
            repo1_url=repo1_url,
            dccscr_whitelists_branch=dccscr_whitelists_branch,
        )
    except Exception:
        logger.exception("Failed to generate ironbank.yaml")
        return

    # Stop processing at this point for a dry run
    if dry_run:
        return

    actions = [
        {
            "action": "create",
            "file_path": "ironbank.yaml",
            "content": "TODO",
        },
    ]

    for path in ("Jenkinsfile", "download.json", "download.yaml"):
        if path in tree:
            actions.append(
                {
                    "action": "delete",
                    "file_path": path,
                }
            )

    try:
        # https://docs.gitlab.com/ee/api/commits.html#create-a-commit-with-multiple-files-and-actions
        gl_project.commits.create(
            {
                "commit_message": "Migrate to ironbank.yaml",
                "branch": branch,
                "start_branch": start_branch,
                "actions": actions,
            }
        )
    except gitlab.exceptions.GitlabError:
        logger.exception(f"Failed to create commit on {project}")
        return

    try:
        # https://docs.gitlab.com/ee/api/merge_requests.html#create-mr
        gl_project.mergerequests.create(
            {
                "source_branch": branch,
                "target_branch": start_branch,
                "title": "Migrate to ironbank.yaml",
                "labels": ["ironbank.yaml migration"],
                "description": MR_DESCRIPTION,
            }
        )
    except gitlab.exceptions.GitlabError:
        logger.exception(f"Failed to make MR on {project}")
        return

    logger.info(f"MR successfully created on {project}")


def _list_greylists(repo1_url):
    """
    Create the list of greylists from dccscr-whitelists repo
    """
    whitelist_dir = "dccscr-whitelists"
    whitelist_repo_url = f"{repo1_url}/dsop/{whitelist_dir}.git"
    logger.info(f"Cloning {whitelist_repo_url}")

    with tempfile.TemporaryDirectory() as tempdir:
        git.Repo.clone_from(whitelist_repo_url, tempdir)
        for greylist in Path(tempdir).glob("**/*.greylist"):
            yield greylist.relative_to(tempdir)


if __name__ == "__main__":
    main()
