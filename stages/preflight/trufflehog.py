#!/usr/bin/env python3

import logging
import os
import sys
import subprocess
import git
import yaml
from typing import Optional
from pathlib import Path


def main() -> None:
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")

    repo_dir = os.environ["CI_PROJECT_DIR"]
    pipeline_repo_dir = os.environ["PIPELINE_REPO_DIR"]
    branch_name = os.environ["CI_COMMIT_BRANCH"]
    job_image = os.environ["CI_JOB_IMAGE"]

    project_truffle_config = Path(repo_dir, "trufflehog-config.yaml")
    default_truffle_config = Path(
        pipeline_repo_dir,
        "stages/preflight/default-trufflehog-config.yaml",
    )

    diff_branch = (
        "origin/development" if branch_name != "development" else "origin/master"
    )

    # Check if trufflehog.yaml file exists and exit(1) if it does
    if Path(repo_dir, "trufflehog.yaml").is_file():
        logging.error("trufflehog.yaml file is not permitted to exist in repo")
        sys.exit(1)

    history_cmd = get_history_cmd(repo_dir, diff_branch)
    create_trufflehog_config(project_truffle_config, default_truffle_config, repo_dir)

    cmd = [
        "trufflehog3",
        "--no-entropy",
        "--branch",
        branch_name,
        *history_cmd,
        "--config",
        "trufflehog-config.yaml",
        ".",
    ]

    logging.info(f'truffleHog command: {" ".join(cmd)}')
    th_flags = " ".join(cmd[1:-1])

    try:
        logging.info("Scanning with truffleHog")
        findings = subprocess.run(
            args=cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            check=True,
        )
        assert findings.returncode == 0
    except subprocess.CalledProcessError as e:
        if e.returncode == 1 and e.stdout:
            logging.error(f"Return code: {e.returncode}")
            logging.error("truffleHog found secrets")
            msg = f"docker run -it --rm -v $(pwd):/proj {job_image} {th_flags} /proj"
            logging.error("=" * len(msg))
            logging.error("The offending commits must be removed from commit history")
            logging.error(
                "Secrets committed to a git repository are considered exposed and should be rolled immediately"
            )
            logging.error(
                "To review truffleHog findings locally run the following command from the root of your project"
            )
            logging.error(msg)
        else:
            logging.error(f"Return code: {e.returncode}")
            logging.error("truffleHog scan failed")
        sys.exit(1)
    except AssertionError:
        logging.error("truffleHog returned a non-zero exit code")
        sys.exit(1)
    logging.info("truffleHog found no secrets")


def get_history_cmd(repo_dir, diff_branch) -> list[str]:
    """
    Uses gitpython to get a list of commit shasums of feature branch commits that don't exist in development
    Returns a list of truffleHog3 flags
        [--since-commit, the oldest sha in the commits list]
        if list is empty [--no-history]
    """
    # fetch origin before performing a git log
    repo = git.Repo(repo_dir)
    origin = repo.remotes.origin.fetch()
    assert diff_branch in [x.name for x in origin]
    commits = repo.git.rev_list(
        f"{diff_branch}..",
        "--no-merges",
    ).split("\n")
    formatted_commits = "\n".join([x for x in commits])
    logging.info(f"git rev-list {diff_branch}.. --no-merges\n{formatted_commits}")
    # if no data is returned to commits, it will be an list with one element that is an empty string
    return ["--since-commit", commits[-1]] if commits[-1] else ["--no-history"]


def get_config(config_file: PosixPath = None) -> tuple[list, list]:
    skip_strings = []
    skip_paths = []
    with config_file.open(mode="r") as f:
        data = yaml.safe_load(f)
    keys = [key for key in data]
    if "skip_strings" in keys:
        skip_strings = data["skip_strings"]
    if "skip_paths" in keys:
        skip_paths = data["skip_paths"]
    return skip_strings, skip_paths


if __name__ == "__main__":
    main()
