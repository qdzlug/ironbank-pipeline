from requests import Session

import math

from dataclasses import dataclass
from .decorators import request_retry
from ironbank.pipeline.utils import logger

log = logger.setup("paginated_request")


@dataclass
class PaginatedRequest:
    session: Session
    url: str
    query: str = ""
    page: int = 1
    page_size: int = 100
    total_count_header: str = "x-total-count"

    @request_retry(5)
    def __post_init__(self):
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
        for page in range(0, self.total_pages):
            response = self.session.get(
                self.url,
                params={"page": page, "page_size": self.page_size, "q": self.query},
            )
            response.raise_for_status()
            yield response.json()
