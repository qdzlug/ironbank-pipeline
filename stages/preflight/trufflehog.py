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
    pipeline_repo_dir = os.environ.get(
        "PIPELINE_REPO_DIR",
        os.environ["CI_PROJECT_DIR"],
    )
    branch_name = os.environ["CI_COMMIT_BRANCH"]
    job_image = os.environ["CI_JOB_IMAGE"]
    config_variable = os.environ.get("TRUFFLEHOG_CONFIG")

    if Path(repo_dir, "trufflehog-config.yaml").is_file():
        config_file = "trufflehog-config.yaml"
    elif Path(repo_dir, "trufflehog-config.yml").is_file():
        config_file = "trufflehog-config.yml"
    else:
        logging.info("custom trufflehog configuration not detected")
        config_file = "default-trufflehog-config.yaml"

    project_truffle_config = Path(
        repo_dir,
        config_file,
    )
    default_truffle_config = Path(
        pipeline_repo_dir,
        "stages/preflight/default-trufflehog-config.yaml",
    )

    project_origin = os.environ.get("TRUFFLEHOG_TARGET", "cht")

    if project_origin == "pipeline":
        diff_branch = "origin/master"
    else:
        diff_branch = (
            "origin/development" if branch_name != "development" else "origin/master"
        )

    # Check if trufflehog.yaml file exists and exit(1) if it does
    if Path(repo_dir, "trufflehog.yaml").is_file():
        logging.error("trufflehog.yaml file is not permitted to exist in repo")
        sys.exit(1)

    commit_diff = get_commit_diff(repo_dir, diff_branch)
    history_cmd = get_history_cmd(commit_diff)
    project_config = create_trufflehog_config(
        project_truffle_config, default_truffle_config, repo_dir, config_variable
    )

    cmd = [
        "trufflehog3",
        "--no-entropy",
        "--branch",
        branch_name,
        *history_cmd,
        "--config",
        config_file,
        ".",
    ]

    # if project has a config file and the config variable is set,
    #   use cmd value to print debug command for pipeline users
    # if either is false, remove the "--config" flag from the printed command
    if project_config:
        printed_cmd = cmd
    else:
        printed_cmd = cmd[:-3] + cmd[-1:]

    logging.info(f'truffleHog command: {" ".join(cmd)}')
    th_flags = " ".join(printed_cmd[1:-1])

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


def get_commit_diff(repo_dir: str, diff_branch: str) -> str:
    """
    Uses gitpython to get a list of commit shasums of feature branch commits that don't exist in development,
    or for commits in development that aren't in master when CI_COMMIT_BRANCH is development
    Returns a string of commit SHAs separated by newline characters
    """
    # fetch origin before performing a git log
    repo = git.Repo(repo_dir)
    commits = repo.git.rev_list(
        f"{diff_branch}..",
        "--no-merges",
    )
    logging.info(f"git rev-list {diff_branch}.. --no-merges")
    return commits


def get_history_cmd(commits: str) -> list[str]:
    """
    Splits a string of newline separated commit SHAs
    Returns a list of truffleHog3 flags
        [--since-commit, the oldest sha in the commits list]
        if list is empty [--no-history]
    """
    commit_lst = commits.split("\n")
    for commit in commit_lst:
        logging.info(commit)
    # if no data is returned to commits, since_commit will be an empty string
    since_commit: str = commit_lst[-1]
    return ["--since-commit", since_commit] if since_commit else ["--no-history"]


def get_config(config_file: Path, expand_vars: bool = False) -> tuple[dict, list]:
    """
    Loads a trufflehog config yaml file and pulls out the skip_strings and skip_paths values
    """
    skip_strings = {}
    skip_paths = []
    if config_file.is_file():
        logging.debug("Config file found")
        with config_file.open(mode="r") as f:
            data: dict = yaml.safe_load(f)
        if "skip_strings" in data:
            skip_strings = data["skip_strings"]
        if "skip_paths" in data:
            skip_paths = (
                [os.path.expandvars(x) for x in data["skip_paths"]]
                if expand_vars
                else data["skip_paths"]
            )
    else:
        logging.debug("Config file not found")
    return skip_strings, skip_paths


def create_trufflehog_config(
    project_config_path: Path,
    default_config_path: Path,
    repo_dir: str,
    config_variable: Optional[str] = None,
) -> bool:
    """
    Loads the default trufflehog config and if a project config exists loads that as well.
    Then concatonates the default and project configs and writes these to a file.
    Returns a boolean.
        True if the config variable exists and a config file is found
    """
    default_config_skip_strings, default_config_skip_paths = get_config(
        default_config_path, True
    )
    project_config_skip_strings, project_config_skip_paths = (
        get_config(project_config_path) if config_variable else ({}, [])
    )
    skip_strings = project_config_skip_strings
    skip_strings.update(
        {
            k: v
            for (k, v) in default_config_skip_strings.items()
            if k not in skip_strings
        }
    )
    skip_paths = project_config_skip_paths + [
        x for x in default_config_skip_paths if x not in project_config_skip_paths
    ]
    config = {
        "skip_strings": skip_strings,
        "skip_paths": skip_paths,
    }
    outfile = Path(repo_dir, project_config_path)
    with outfile.open(mode="w") as of:
        yaml.safe_dump(config, of, indent=2, sort_keys=False)
    return True if config_variable and project_config_path.is_file() else False


if __name__ == "__main__":
    main()
