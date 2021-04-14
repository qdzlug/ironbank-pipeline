#!/usr/bin/python3
import json
import logging
import os
import sys
import requests
import git
from pathlib import Path

# def main():
#   report_name = "trufflehog.json"
branch_name = os.environ["CI_COMMIT_BRANCH"]
project_id = os.environ["CI_PROJECT_ID"]
# pipeline_sha = last_pipeline_sha(branch_name, project_id)

# since_commit_cmd = (
#   ["--since_commit", pipeline_sha[0]['sha']]
#   if pipeline_sha[0]
#   else ["--no-history"]
# )


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
        pipelines = [x for x in r.json() if x["status"] not in ["canceled", "skipped"]]
    else:
        logging.error("Non 200 status code returned from pipeline sha retrieval")
        logging.error(f"Response text: {r.text}")
        sys.exit(1)
    if pipelines:
        return pipelines
    return None


pipelines = last_pipeline_sha(branch_name, project_id)
print(pipelines)
print(f"Current commit: {os.environ['CI_COMMIT_SHA']}")
print(f"Last pipeline run from API: {pipelines[0]['sha']}")
