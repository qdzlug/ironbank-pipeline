#!/usr/bin/env python3

import argparse
import os
import sys
import tempfile
from pathlib import Path
import logging

import git

logging.basicConfig(level=logging.WARNING, stream=sys.stdout)
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

    logger.setLevel(args.log_level)

    with tempfile.TemporaryDirectory(prefix="ironbank-yaml-migration-") as tempdir:
        projects = _list_projects(args.repo1_url, tempdir)

    for project in projects:
        logger.info(f"Processing {project}")

        # if gitlab branch exists:
        #   logger.info branch exists
        #   continue

        # if gitlab project has ironbank.yaml:
        #   logger.info ironbank.yaml exists
        #   continue

        # try:
        #   yaml = generate.generate(repo1_url, project_name)
        # except:
        #   log error

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


def _list_projects(repo1_url, path):
    """
    Create the list of projects from greylist files
    """
    whitelist_dir = "dccscr-whitelists"
    whitelist_repo_url = f"{repo1_url}/dsop/{whitelist_dir}.git"
    logger.info(f"Cloning {whitelist_repo_url}")
    git.Repo.clone_from(whitelist_repo_url, path)
    for greylist in Path(path).glob("**/*.greylist"):
        # Everything but the *.greylist filename is the image name
        yield "/".join(greylist.relative_to(path).parts[:-1])


if __name__ == "__main__":
    sys.exit(main())
