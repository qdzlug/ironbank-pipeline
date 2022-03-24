#!/usr/bin/env python3

import os
import pathlib
import logging
import requests
import json
import sys


def load_data() -> dict:
    """
    loads the repo_map file and returns the latest build dict
    """
    build_id = os.environ["CI_PIPELINE_ID"]
    current_dir = os.getcwd()
    filename = pathlib.Path(f"{current_dir}/repo_map.json")
    with filename.open(mode="r") as f:
        data: dict[str, dict] = json.load(f)
    return data[build_id]


def post_artifact_data_vat():
    vat_endpoint = (
        f"{os.environ['VAT_BACKEND_SERVER_ADDRESS']}/internal/import/artifacts"
    )
    post_resp = requests.post(
        vat_endpoint,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['CI_JOB_JWT']}",
        },
        json={
            "containerName": os.environ["IMAGE_NAME"],
            "containerVersion": os.environ["IMAGE_TAG"],
            "publishedTimestamp": os.environ["directory_date"],
            "readme": os.environ["project_readme"],
            "license": os.environ["project_license"],
            "tar": os.environ["tar_location"],
        },
    )
    return post_resp


def post_artifact_data_ibfe(new_data: dict):
    post_resp = requests.post(
        os.environ["IBFE_API_ENDPOINT"],
        headers={
            "Authorization": os.environ["IBFE_API_KEY"],
            "x-gitlab-ci-jwt": f"Bearer {os.environ['CI_JOB_JWT']}",
        },
        json=new_data,
    )
    return post_resp


def main():
    if os.environ["CI_COMMIT_BRANCH"] == "master":
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

        new_data = load_data()
        try:
            app = "IBFE"
            post_resp = post_artifact_data_ibfe(new_data)
            post_resp.raise_for_status()
            logging.info(f"Uploaded container data to {app} API")
            app = "VAT"
            post_resp = post_artifact_data_vat()
            post_resp.raise_for_status()
            logging.info(f"Uploaded container data to {app} API")
        except requests.exceptions.Timeout:
            logging.exception("Unable to reach the IBFE API, TIMEOUT.")
            sys.exit(1)
        except requests.exceptions.HTTPError:
            logging.error(f"Got HTTP {post_resp.status_code}")
            logging.exception(f"{app} HTTP error")
            sys.exit(1)
        except requests.exceptions.RequestException:
            logging.exception(f"Error submitting container data to {app} API")
            sys.exit(1)
        except Exception:
            logging.exception(f"Unhandled exception for {app}")
            sys.exit(1)
    else:
        logging.debug("Skipping use of vat artifacts and ibfe build endpoints")


if __name__ == "__main__":
    main()
