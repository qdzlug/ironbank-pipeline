#!/usr/bin/env python3

import argparse
import os
import sys
import tempfile
from pathlib import Path
import logging

import git
import generate
import gitlab

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

    with tempfile.TemporaryDirectory(prefix="ironbank-yaml-migration-") as tempdir:
        greylists = _list_greylists(args.repo1_url, tempdir)

    gl = gitlab.Gitlab(args.repo1_url, private_token=args.repo1_token)

    for greylist in greylists:
        # Path to the greylist in the repo
        greylist_path = greylist.as_posix()
        # Everything but the final *.greylist filename is the project name
        project = "dsop/" + "/".join(greylist.parts[:-1])

        logger.info(f"Processing {project}")

        try:
            gl_project = gl.projects.get(project, lazy=True)
            branches = [b.name for b in gl_project.branches.list()]
            if not args.start_branch in branches:
                logger.error(f"{project} does not have {args.start_branch} branch")
                continue
            if args.branch in branches:
                logger.info(
                    f"{project} already has {args.branch} branch, skipping yaml generation"
                )
                continue
        except gitlab.exceptions.GitlabListError:
            # Old greylists like dsop/opensource/foo/1.2.3/foo-1.2.3.greylist will result in an error that can be ignored
            logger.error(f"Failed to get branches for {project}")
            continue

        # if gitlab project has ironbank.yaml:
        #   logger.info ironbank.yaml exists
        #   continue

        try:
            yaml = generate.generate(
                greylist_path=greylist_path, repo1_url=args.repo1_url
            )
        except Exception:
            logger.exception("Failed to generate ironbank.yaml")
            continue

        # Stop processing at this point for a dry run
        if args.dry_run:
            continue

        # try:
        #   commit = create gitlab commit and branch
        #   https://docs.gitlab.com/ee/api/commits.html#create-a-commit-with-multiple-files-and-actions
        #     actions:
        #        delete download.yaml download.json jenknsfile
        #        create ironbank.yaml
        #   mr = make gitlab mr
        # except:
        #   log error

    return 0


def _list_greylists(repo1_url, path):
    """
    Create the list of grelists from dccscr-whitelists repo
    """
    whitelist_dir = "dccscr-whitelists"
    whitelist_repo_url = f"{repo1_url}/dsop/{whitelist_dir}.git"
    logger.info(f"Cloning {whitelist_repo_url}")
    git.Repo.clone_from(whitelist_repo_url, path)
    for greylist in Path(path).glob("**/*.greylist"):
        yield greylist.relative_to(path)


if __name__ == "__main__":
    sys.exit(main())
