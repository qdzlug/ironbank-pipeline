from dataclasses import dataclass
import requests
import os

from .utils import logger
from .utils.decorators import request_error_handler


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


@dataclass
class VatAPI(API):
    log = logger.setup(name="API.VatAPI")
    app: str = "VAT"
    container_route: str = "/p1/container"
    import_route: str = "/internal/import"
    import_scan_route: str = f"{import_route}/scan"
    import_access_route: str = f"{import_route}/check-access"
    import_artifacts_route: str = f"{import_route}/artifacts"

    # Not used in pipeline, added to potentially support outside tools
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
    def check_access(self, image_name, create_request=False) -> None:
        self.log.info(f"Checking access to {image_name}")
        self.log.info(f"{self.url}{self.import_access_route}/?name={image_name}")
        self.response = requests.get(
            f"{self.url}{self.import_access_route}/?name={image_name}",
            params={"createRequest": create_request},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.environ['CI_JOB_JWT_V2']}",
            },
        )
        self.response.raise_for_status()
