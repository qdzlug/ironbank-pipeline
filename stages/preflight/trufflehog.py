#!/usr/bin/python3

import logging
import os
import sys
import subprocess
import git


def main():
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
    branch_name = os.environ["CI_COMMIT_BRANCH"]

    origin = git.Repo(repo_dir).remotes.origin.fetch()
    assert "origin/development" in [x.name for x in origin]
    history_cmd = get_history_cmd(repo_dir)

    cmd = [
        "trufflehog3",
        "--no-entropy",
        "--branch",
        branch_name,
        *history_cmd,
        ".",
    ]

    logging.info(f'truffleHog command: {" ".join(cmd)}')
    th_flags = " ".join(cmd[1:-1])
    job_image = os.environ["CI_JOB_IMAGE"]

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
            logging.error(f"truffleHog found secrets")
            logging.error("=" * 145)
            logging.error(
                "To review truffleHog findings locally run the following command from the root of your project"
            )
            logging.error(
                f"docker run -it --rm -v $(pwd):/proj {job_image} {th_flags} /proj"
            )
            sys.exit(1)
        else:
            logging.error(f"Return code: {e.returncode}")
            logging.error("truffleHog scan failed")
            sys.exit(1)
    logging.info("truffleHog found no secrets")


def get_history_cmd(repo_dir):
    repo = git.Repo(repo_dir)
    commits = list(repo.iter_commits("origin/development.."))
    logging.info([x.hexsha for x in commits])
    return ["--since-commit", commits[-1:][0].hexsha] if commits else ["--no-history"]


if __name__ == "__main__":
    main()
