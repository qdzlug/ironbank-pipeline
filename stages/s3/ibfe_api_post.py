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
            post_resp = requests.post(
                os.environ["IBFE_API_ENDPOINT"],
                headers={
                    "Authorization": os.environ["IBFE_API_KEY"],
                    "x-gitlab-ci-jwt": f"Bearer {os.environ['CI_JOB_JWT']}",
                },
                json=new_data,
            )
            post_resp.raise_for_status()
            logging.info("Uploaded container data to IBFE API")
        except requests.exceptions.Timeout:
            logging.exception("Unable to reach the IBFE API, TIMEOUT.")
            sys.exit(1)
        except requests.exceptions.HTTPError:
            logging.error(f"Got HTTP {post_resp.status_code}")
            if post_resp.status_code == 500 :
                logging.error("HTTP error: 500 likely received due to duplicate org.opencontainers.image.title and version. Please investigate ironbank.dso.mil to see if something already exists.")
            logging.exception("HTTP error")
            sys.exit(1)
        except requests.exceptions.RequestException:
            logging.exception("Error submitting container data to IBFE API")
            sys.exit(1)
        except Exception:
            logging.exception("Unhandled exception")
            sys.exit(1)
    else:
        logging.debug("Skipping use of ibfe api build endpoint")


if __name__ == "__main__":
    main()
