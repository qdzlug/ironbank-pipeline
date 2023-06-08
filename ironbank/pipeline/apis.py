from dataclasses import dataclass

import requests

from .utils import logger
from .utils.decorators import vat_request_error_handler


@dataclass
class API:
    """
    A dataclass for handling API interactions.

    This class is used to setup the API endpoint, provide authentication, handle responses 
    and any additional requirements.

    Attributes
    ----------
    log : logger.Logger
        A logger object to handle log messages.
    url : str
        The URL for the API endpoint.
    auth : str, optional
        The authentication string to be used for API calls. Default is an empty string.
    response : requests.Response, optional
        The Response object to store the response of API calls. Default is None.
    app : str, optional
        The name of the application interacting with the API. Default is an empty string.

    Methods
    -------
    validate_url():
        Validates that the URL provided is valid.

    format_url():
        Updates the formatting for the URL if it is valid.

    validate_data():
        Confirms that the data provided is either a string or JSON and that it is valid.

    Note: The methods are not implemented in this snippet.
    """
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
    """
    A dataclass representing the VAT API.

    This class is used to interact with the VAT API. It provides methods for getting image details,
    checking access rights to an image, and handling VAT API requests.

    Attributes
    ----------
    log : logger
        Logger instance used for logging.
    app : str
        The name of the application, default is "VAT".
    container_route : str
        The route used to fetch container details, default is "/p1/container".
    import_route : str
        The route used for import-related requests, default is "/internal/import".
    import_scan_route : str
        The route used for import scan requests, default is "/internal/import/scan".
    import_access_route : str
        The route used to check access for import requests, default is "/internal/import/check-access".
    import_artifacts_route : str
        The route used for import artifacts requests, default is "/internal/import/artifacts".

    Methods
    -------
    get_image(image_name: str, image_tag: str) -> dict
        Fetches image details from the VAT API using `image_name` and `image_tag`.
    check_access(image_name: str, auth: str, create_request: bool = False) -> None
        Checks the access rights to the specified image. Sends a GET request to the import access route.
    """
    log = logger.setup(name="API.VatAPI")
    app: str = "VAT"
    container_route: str = "/p1/container"
    import_route: str = "/internal/import"
    import_scan_route: str = f"{import_route}/scan"
    import_access_route: str = f"{import_route}/check-access"
    import_artifacts_route: str = f"{import_route}/artifacts"

    @vat_request_error_handler
    def get_image(self, image_name, image_tag) -> dict:
        """
        Fetches image details from the VAT API using `image_name` and `image_tag`.

        Note: This function is not currently used in the pipeline, it is included for future use.

        Parameters
        ----------
        image_name : str
            The name of the image.
        image_tag : str
            The tag of the image.

        Returns
        -------
        dict or None
            A dictionary with image details if found, else None.

        Raises
        ------
        requests.exceptions.HTTPError
            If the status code is not 200 (OK) or 404 (Not Found).
        """
        self.log.info("Getting image information from vat api")
        self.response = requests.get(
            f"{self.url}{self.container_route}",
            params={"name": image_name, "tag": image_tag},
            timeout=(30, 30),
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
