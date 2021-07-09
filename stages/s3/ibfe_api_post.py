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
        new_data = load_data()
        try:
            post_resp = requests.post(
                os.environ["IBFE_API_ENDPOINT"],
                headers={"Authorization": os.environ["IBFE_API_KEY"]},
                json=new_data,
            )
            logging.info("Uploaded container data to IBFE API")
            post_resp.raise_for_status()
        except requests.exceptions.Timeout as req_timeout:
            logging.error(
                f"Unable to reach the IBFE API, TIMEOUT. stack trace\n{req_timeout}"
            )
            sys.exit(1)
        except requests.exceptions.HTTPError as http_err:
            logging.info(f"Got HTTP {post_resp.status_code}")
            logging.error(f"HTTP error\n{http_err}")
            sys.exit(1)
        except requests.exceptions.RequestException as request_e:
            logging.error(f"Error submitting container data to IBFE API\n{request_e}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Unhandled exception\n{e}")
            sys.exit(1)
    else:
        logging.debug("Skipping use of ibfe api build endpoint")


if __name__ == "__main__":
    main()
