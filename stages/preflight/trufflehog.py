#!/usr/bin/python3

import logging
import os
import sys
import subprocess
from urllib.parse import urlencode
from urllib.request import urlopen
from urllib.error import HTTPError


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

    branch_name = os.environ["CI_COMMIT_BRANCH"]
    project_id = os.environ["CI_PROJECT_ID"]
    current_commit_sha = os.environ["CI_COMMIT_SHA"]

    pipelines = last_pipeline_sha(branch_name, project_id)
    if pipelines:
        logging.info(f"Current commit: {current_commit_sha}")
        logging.info(f"Last pipeline run from API: {pipelines[0]['sha']}")

    since_commit_cmd = since_commit_sha(pipelines, current_commit_sha)

    print(since_commit_cmd)

    cmd = [
        "trufflehog3",
        "--no-entropy",
        "--branch",
        branch_name,
        *since_commit_cmd,
        ".",
    ]

    logging.info(" ".join(cmd))

    try:
        findings = subprocess.run(
            args=cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        )
    except subprocess.CalledProcessError:
        (
            logging.error("truffleHog found secrets")
            if findings.returncode == 1 and findings.stdout
            else logging.error("truffleHog scan failed") and sys.exit(1)
        )


def last_pipeline_sha(branch_name, project_id):
    """
    Uses requests to call GitLab API to get list of pipelines
    Then retrieves the commit shasums of successful pipelines
    Returns:
        list of shasums for successful pipeline runs for given project and branch
        None if pipelines list is empty
    """
    url = f"https://repo1.dso.mil/api/v4/projects/{project_id}/pipelines"
    params = {"ref": branch_name}
    url += "?" + urlencode(params)
    try:
        with urlopen(url) as response:
            r = response.read().decode()
    except HTTPError as e:
        logging.error("Pipeline list retrieval failed")
        logging.error(e.status)
        logging.error(e.reason)
        sys.exit(1)
    except Exception:
        e = sys.exc_info()[0]
        logging.error("Something went wrong")
        logging.error(e)
        sys.exit(1)
    if r.status == 200:
        pipelines = [x for x in r.json() if x["status"] == "success"]
    else:
        logging.error("Non 200 status code returned from pipeline sha retrieval")
        logging.error(f"Response text: {r.text}")
        sys.exit(1)
    if pipelines:
        return pipelines
    return None


def since_commit_sha(pipelines, current_commit_sha, pipeline_sha_lst=[]):
    """
    expects a list of pipeline shasums
    adds sha to list if sha is not the same as the current CI_COMMIT_SHA
    intent is to use the first element of the pipeline_sha_list
    if there is no element to select from use no history flag
    Returns:
        list with truffleHog3 options
            --since-commit <first element of pipeline_sha_lst>
            --no-history
    """
    if pipelines:
        for sha in [x["sha"] for x in pipelines if x["sha"] != current_commit_sha]:
            pipeline_sha_lst.append(sha)
    return (
        ["--since-commit", pipeline_sha_lst[0]]
        if pipeline_sha_lst
        else ["--no-history"]
    )


if __name__ == "__main__":
    main()
