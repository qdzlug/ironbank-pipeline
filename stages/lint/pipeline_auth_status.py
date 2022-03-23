import requests
import urllib.parse
import logging
import os
import sys

from requests.models import HTTPError
from requests.structures import CaseInsensitiveDict


def main() -> None:
    base_url = os.environ["VAT_BACKEND_SERVER_ADDRESS"]
    url_encoded_container_name = urllib.parse.quote(os.environ["IMAGE_NAME"], safe="")
    url = f"{base_url}/internal/import/check-access/{url_encoded_container_name}"
    params = {"createRequest": "true"}
    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = f"Bearer {os.environ['CI_JOB_JWT_V2']}"
    logging.info(f"Request URL: {url}")
    try:
        r = requests.get(url, headers=headers, params=params)
        r.raise_for_status()
        logging.info("Retrieve Auth Status from VAT")
        logging.info(f"Response: {r.text}")
        logging.debug(f"JSON Response:\n{r.json}")
    except HTTPError:
        if r.status_code == 403:
            logging.info(
                f"{os.environ['CI_PROJECT_NAME']} is not authorized to use the image name of: {os.environ['IMAGE_NAME']}. Either the name has changed or the container has never been tracked in VAT. An authorization request has automatically been generated. Please create a ticket with the link below for VAT authorization review."
            )
            logging.info(
                f"https://repo1.dso.mil/dsop/dccscr/-/issues/new?issuable_template=VAT%20Pipeline%20Access%20Request&issue[title]=VAT+Pipeline+Access+Request+{urllib.parse.quote(os.environ['CI_PROJECT_URL'], safe='')}"
            )
        else:
            logging.exception("HTTPError")
        sys.exit(1)


if __name__ == "__main__":
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            filename="new_vat_import_logging.out",
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")
    main()
