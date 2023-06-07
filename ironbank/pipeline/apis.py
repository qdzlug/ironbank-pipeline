from dataclasses import dataclass

import requests

from .utils import logger
from .utils.decorators import vat_request_error_handler


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
    @vat_request_error_handler
    def get_image(self, image_name, image_tag) -> dict:
        self.log.info("Getting image information from vat api")
        self.response = requests.get(
            f"{self.url}{self.container_route}",
            params={"name": image_name, "tag": image_tag},
            timeout=(30, 30)
        )
        try:
            self.response.raise_for_status()
        except requests.exceptions.HTTPError:
            if self.response.status_code == 404:
                self.log.warning(f"{image_name}:{image_tag} not found in {self.app}")
                self.log.warning(self.response.text)
        self.log.info("Fetched data from vat successfully")
        return self.response.json() if self.response.status_code == 200 else None

    @vat_request_error_handler
    def check_access(self, image_name, auth, create_request=False) -> None:
        """
        Checks the access rights to the specified image. Sends a GET request to the import access route.

        Parameters
        ----------
        image_name : str
            Name of the image for which access rights are to be checked.
        auth : str
            The authorization token used to authenticate the request.
        create_request : bool, optional
            A flag to determine whether a new request should be created if it does not exist (default is False).

        Raises
        ------
        HTTPError
            If the request to the import access route returns a status indicating an error.
        """
        self.log.info(f"Checking access to {image_name}")
        self.log.info(f"{self.url}{self.import_access_route}/?name={image_name}")
        self.response = requests.get(
            f"{self.url}{self.import_access_route}",
            params={"name": image_name, "createRequest": create_request},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {auth}",
            },
            timeout=(30, 30)
        )
        self.response.raise_for_status()
