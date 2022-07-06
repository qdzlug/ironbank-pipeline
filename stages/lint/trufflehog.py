#!/usr/bin/env python3

import os
import sys
import subprocess
import git
import yaml
from typing import Optional
from pathlib import Path


sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ironbank/pipeline"
    )
)

from project import DsopProject  # noqa: E402
from utils import logger  # noqa: E402

log = logger.setup(name="lint.trufflehog")


def get_commit_diff(repo_dir: str, diff_branch: str) -> str:
    """
    Uses gitpython to get a list of commit shasums of feature branch
    commits that don't exist in development, or for commits in
    development that aren't in master when CI_COMMIT_BRANCH is development
    Returns a string of commit SHAs separated by newline characters
    """
    # fetch origin before performing a git log
    repo = git.Repo(repo_dir)
    commits = repo.git.rev_list(
        f"{diff_branch}..",
        "--no-merges",
    )
    log.info(f"git rev-list {diff_branch}.. --no-merges")
    return commits


def get_history_cmd(commits: str) -> list[str]:
    """
    Splits a string of newline separated commit SHAs
    Returns a list of truffleHog3 flags
        [--since, the oldest sha in the commits list]
        if list is empty [--no-history]
    """
    commit_lst = commits.split("\n")
    for commit in commit_lst:
        log.info(commit)
    # if no data is returned to commits, since_commit will be an empty string
    since_commit: str = commit_lst[-1]
    return ["--since", since_commit] if since_commit else ["--no-history"]


def get_config(config_file: Path, expand_vars: bool = False) -> list:
    """
    Loads a trufflehog config yaml file and pulls out the skip_strings and skip_paths values
    """
    exclude_list = []
    if config_file.is_file():
        log.debug("Config file found")
        with config_file.open(mode="r") as f:
            data: dict = yaml.safe_load(f)
        exclude_list = data["exclude"]
        if expand_vars:
            for item in exclude_list:
                item["paths"] = [os.path.expandvars(x) for x in item["paths"]]

    else:
        log.debug("Config file not found")
    return exclude_list


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
    default_exclude_list = get_config(default_config_path, True)
    project_exclude_list = get_config(project_config_path) if config_variable else []
    config = {"exclude": default_exclude_list + project_exclude_list}
    outfile = Path(repo_dir, project_config_path)
    with outfile.open(mode="w") as of:
        yaml.safe_dump(config, of, indent=2, sort_keys=False)
    return True if config_variable and project_config_path.is_file() else False


def main() -> None:
    repo_dir = os.environ["CI_PROJECT_DIR"]
    pipeline_repo_dir = os.environ.get(
        "PIPELINE_REPO_DIR",
        os.environ["CI_PROJECT_DIR"],
    )
    branch_name = os.environ["CI_COMMIT_BRANCH"]
    job_image = os.environ["CI_JOB_IMAGE"]
    config_variable = os.environ.get("TRUFFLEHOG_CONFIG")

    dsop_project = DsopProject()

    project_truffle_config = Path(
        repo_dir,
        dsop_project.trufflehog_conf_path,
    )
    default_truffle_config = Path(
        pipeline_repo_dir,
        "stages/lint/default-trufflehog-config.yaml",
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
        log.error("trufflehog.yaml file is not permitted to exist in repo")
        sys.exit(1)

    commit_diff = get_commit_diff(repo_dir, diff_branch)
    history_cmd = get_history_cmd(commit_diff)
    project_config = create_trufflehog_config(
        project_truffle_config, default_truffle_config, repo_dir, config_variable
    )

    cmd = [
        "trufflehog3",
        "--no-entropy",
        "--ignore-nosecret",
        "--branch",
        branch_name,
        *history_cmd,
        "--config",
        dsop_project.trufflehog_conf_path.as_posix(),
        ".",
    ]

    # if project has a config file and the config variable is set,
    #   use cmd value to print debug command for pipeline users
    # if either is false, remove the "--config" flag from the printed command
    if project_config:
        printed_cmd = cmd
    else:
        printed_cmd = cmd[:-3] + cmd[-1:]

    log.info(f'truffleHog command: {" ".join(cmd)}')
    th_flags = " ".join(printed_cmd[1:-1])

    try:
        log.info("Scanning with truffleHog")
        findings = subprocess.run(
            args=cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            check=True,
        )
        assert findings.returncode == 0
    except subprocess.CalledProcessError as e:
        if e.returncode == 2 and e.stdout:
            log.error(f"Return code: {e.returncode}")
            log.error("truffleHog found secrets")
            msg = f"docker run -it --rm -v $(pwd):/proj {job_image} {th_flags} /proj"
            log.error("=" * len(msg))
            log.error("The offending commits must be removed from commit history")
            log.error(
                "Secrets committed to a git repository are considered exposed and should be rolled immediately"
            )
            log.error(
                "To review truffleHog findings locally run the following command from the root of your project"
            )
            log.error(msg)
        else:
            log.error(f"Return code: {e.returncode}")
            log.error("truffleHog scan failed")
        sys.exit(1)
    except AssertionError:
        log.error("truffleHog returned a non-zero exit code")
        sys.exit(1)
    log.info("truffleHog found no secrets")


if __name__ == "__main__":
    main()
