from dataclasses import dataclass
import requests
import os
import sys
import logging


@dataclass
class API:
    # maybe use urllib type?
    url: str
    auth: str = ""
    response: requests.Response = None
    app: str = ""
    # data: any = {}
    # params: dict = {}
    # headers: dict = {}

    # check that url is valid using urllib
    # def validate_url():

    # update formatting for url if valid
    # def format_url()

    # confirm data type is either str or json
    # confirm data is valid json
    # def validate_data():


def request_error_handler(func):
    def _request_error_handler(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except requests.exceptions.HTTPError:
            if self.response.status_code == 404 and func.__name__ == "get_image":
                logging.warning(
                    f"{kwargs.get('image_name')}:{kwargs.get('image_tag')} not found in {self.app}"
                )
                logging.warning(self.response.text)
            elif self.response.status_code == 400:
                logging.warning(f"Bad request: {self.url}")
                logging.warning(self.response.text)
                sys.exit(1)
            elif self.response.status_code == 403:
                logging.warning(
                    f"{os.environ['CI_PROJECT_NAME']} is not authorized to use the image name of: {kwargs.get('image_name')}. Either the name has changed or the container has never been tracked in VAT. An authorization request has automatically been generated. Please create a ticket with the link below for VAT authorization review."
                )
                logging.info(
                    f"https://repo1.dso.mil/dsop/dccscr/-/issues/new?issuable_template=VAT%20Pipeline%20Access%20Request&issue[title]=VAT+Pipeline+Access+Request+{os.environ['CI_PROJECT_URL']}"
                )
            else:
                logging.warning(
                    f"Unknown response from VAT {self.response.status_code}"
                )
                logging.warning(self.response.text)
                logging.warning(
                    "Failing the pipeline due to an unexpected response from the vat findings api. Please open an issue in this project using the `Pipeline Failure` template to ensure that we assist you. If you need further assistance, please visit the `Team - Iron Bank Pipelines and Operations` Mattermost channel."
                )
                sys.exit(1)
        except requests.exceptions.RequestException:
            logging.warning(f"Could not access VAT API: {self.url}")
            sys.exit(1)
        except Exception as e:
            logging.warning(f"Unexpected exception thrown {e}")
            sys.exit(1)

    return _request_error_handler


@dataclass
class VAT_API(API):
    app: str = "VAT"
    container_route: str = "/p1/container"
    import_route: str = "/internal/import"
    import_scan_route: str = f"{import_route}/scan"
    import_access_route: str = f"{import_route}/check-access"
    import_artifacts_route: str = f"{import_route}/artifacts"

    @request_error_handler
    def get_image(self, image_name, image_tag) -> dict:
        logging.info("Getting image information from vat api")
        self.response = requests.get(
            f"{self.url}{self.container_route}",
            params={"name": image_name, "tag": image_tag},
        )
        self.response.raise_for_status()
        logging.info("Fetched data from vat successfully")
        if self.response.status_code not in [200, 404]:
            sys.exit(1)
        return self.response.json() if self.response.status_code == 200 else None

    @request_error_handler
    def check_access(self, image_name, create_request=False):
        logging.info(f"Checking access to {image_name}")
        logging.info(f"{self.url}{self.import_access_route}/{image_name}")
        self.response = requests.get(
            f"{self.url}{self.import_access_route}/{image_name}",
            params={"createRequest": create_request},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.environ['CI_JOB_JWT']}",
            },
        )
        self.response.raise_for_status()

    @request_error_handler
    def _force_400(self) -> dict:
        logging.info("Forcing 400")
        self.response = requests.post(
            url=f"{self.url}{self.import_scan_route}",
        )
        self.response.raise_for_status()
        if self.response.status_code not in [201]:
            sys.exit(1)
        return self.response
