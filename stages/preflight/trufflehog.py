#!/usr/bin/python3
import json
import logging
import os
import sys
import requests
import git
from pathlib import Path


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

    report_name = "trufflehog.json"
    branch_name = os.environ["CI_COMMIT_BRANCH"]
    project_id = os.environ["CI_PROJECT_ID"]
    current_commit_sha = os.environ["CI_COMMIT_SHA"]

    pipelines = last_pipeline_sha(branch_name, project_id)
    print(pipelines)
    logging.info(f"Current commit: {current_commit_sha}")
    logging.info(f"Last pipeline run from API: {pipelines[0]['sha']}")

    since_commit_cmd = since_commit_sha(pipelines, current_commit_sha)

    print(since_commit_cmd)


def last_pipeline_sha(branch_name, project_id):
    url = f"https://repo1.dso.mil/api/v4/projects/{project_id}/pipelines"
    try:
        r = requests.get(
            url,
            params={
                "ref": branch_name,
            },
        )
    except requests.exceptions.RequestException:
        logging.exception(f"Could not retrieve last pipeline sha")
        sys.exit(1)
    if r.status_code == 200:
        pipelines = [x for x in r.json() if x["status"] == "success"]
    else:
        logging.error("Non 200 status code returned from pipeline sha retrieval")
        logging.error(f"Response text: {r.text}")
        sys.exit(1)
    if pipelines:
        return pipelines
    return None


def since_commit_sha(pipeline_lst, current_commit_sha):
    pipeline_sha_lst = []
    if pipeline_lst:
        for sha in [x["sha"] for x in pipeline_lst if x != current_commit_sha]:
            pipeline_sha_lst.append(sha)
    return (
        ["--since_commit", pipeline_sha_lst[0]]
        if pipeline_sha_lst
        else ["--no-history"]
    )


if __name__ == "__main__":
    sys.exit(main())
