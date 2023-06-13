import math
from dataclasses import dataclass

from requests import Session

from ironbank.pipeline.utils import logger

from .decorators import request_retry

log = logger.setup("paginated_request")


@dataclass
class PaginatedRequest:
    """Dataclass representing a paginated request to a certain URL.

    It provides functionality to get the pages using HTTP GET request.

    Attributes:
    session (Session): A Session object to maintain the requests session.
    url (str): The URL to which the paginated requests are to be sent.
    query (str, optional): Query parameters for the GET request. Defaults to "".
    page (int, optional): The starting page for the request. Defaults to 1.
    page_size (int, optional): The size of a page in the paginated request. Defaults to 100.
    total_count_header (str, optional): Header in the response that contains total page count. Defaults to "x-total-count".
    """

    session: Session
    url: str
    query: str = ""
    page: int = 1
    page_size: int = 100
    total_count_header: str = "x-total-count"

    @request_retry(5)
    def __post_init__(self):
        """Initializes the total_pages attribute of the object after its
        creation.

        It sends a GET request to the URL and sets the total_pages based
        on the response.
        """
        resp = self.session.get(self.url)
        resp.raise_for_status()
        page_count = (
            int(resp.headers[self.total_count_header])
            if self.total_count_header in resp.headers
            else 1
        )
        self.total_pages = (
            math.ceil(page_count / self.page_size) if page_count > 0 else 1
        )

    @request_retry(5)
    def get(self):
        """Sends a GET request for each page from 1 to total_pages. On
        receiving a response, it checks the status and yields the json content
        of the response.

        Yields:
        dict: The json content of the response.
        """
        for page in range(0, self.total_pages):
            response = self.session.get(
                self.url,
                params={"page": page, "page_size": self.page_size, "q": self.query},
            )
            response.raise_for_status()
            yield response.json()
