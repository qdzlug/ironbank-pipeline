from dataclasses import dataclass
import requests
import os

from utils import logger


@dataclass
class API:
    log = logger.setup(name="API")
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
    def _request_error_handler(self, image_name: str = "", *args, **kwargs):
        try:
            return func(self, image_name, *args, **kwargs)
        except requests.exceptions.HTTPError:
            if self.response.status_code == 400:
                self.log.warning(f"Bad request: {self.url}")
                self.log.warning(self.response.text)
            elif self.response.status_code == 403:
                self.log.warning(
                    f"{os.environ['CI_PROJECT_NAME']} is not authorized to use the image name of: {image_name}. Either the name has changed or the container has never been tracked in VAT. An authorization request has automatically been generated. Please create a ticket with the link below for VAT authorization review."
                )
                self.log.info(
                    f"https://repo1.dso.mil/dsop/dccscr/-/issues/new?issuable_template=VAT%20Pipeline%20Access%20Request&issue[title]=VAT+Pipeline+Access+Request+{os.environ['CI_PROJECT_URL']}"
                )
            else:
                self.log.warning(
                    f"Unknown response from VAT {self.response.status_code}"
                )
                self.log.warning(self.response.text)
                self.log.warning(
                    "Failing the pipeline due to an unexpected response from the vat findings api. Please open an issue in this project using the `Pipeline Failure` template to ensure that we assist you. If you need further assistance, please visit the `Team - Iron Bank Pipelines and Operations` Mattermost channel."
                )
        except requests.exceptions.RequestException:
            self.log.warning(f"Could not access VAT API: {self.url}")
        except RuntimeError as runerr:
            self.log.warning(f"Unexpected exception thrown {runerr}")

    return _request_error_handler


@dataclass
class VatAPI(API):
    log = logger.setup(name="API.VatAPI")
    app: str = "VAT"
    container_route: str = "/p1/container"
    import_route: str = "/internal/import"
    import_scan_route: str = f"{import_route}/scan"
    import_access_route: str = f"{import_route}/check-access"
    import_artifacts_route: str = f"{import_route}/artifacts"

    @request_error_handler
    def get_image(self, image_name, image_tag) -> dict:
        self.log.info("Getting image information from vat api")
        self.response = requests.get(
            f"{self.url}{self.container_route}",
            params={"name": image_name, "tag": image_tag},
        )
        try:
            self.response.raise_for_status()
        except requests.exceptions.HTTPError:
            if self.response.status_code == 404:
                self.log.warning(f"{image_name}:{image_tag} not found in {self.app}")
                self.log.warning(self.response.text)
        self.log.info("Fetched data from vat successfully")
        return self.response.json() if self.response.status_code == 200 else None

    @request_error_handler
    def check_access(self, image_name, create_request=False):
        self.log.info(f"Checking access to {image_name}")
        self.log.info(f"{self.url}{self.import_access_route}/{image_name}")
        self.response = requests.get(
            f"{self.url}{self.import_access_route}/{image_name}",
            params={"createRequest": create_request},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.environ['CI_JOB_JWT_V2']}",
            },
        )
        self.response.raise_for_status()

    @request_error_handler
    def _force_400(self) -> dict:
        self.log.info("Forcing 400")
        self.response = requests.post(
            url=f"{self.url}{self.import_scan_route}",
        )
        self.response.raise_for_status()
        return self.response
