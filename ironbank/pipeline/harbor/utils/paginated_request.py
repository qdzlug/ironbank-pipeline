import requests
import math

from dataclasses import dataclass
from ironbank.pipeline.utils.decorators import request_retry


@dataclass
class PaginatedRequest:
    auth: tuple
    url: str
    query: str = ""
    page: int = 1
    page_size: int = 100

    def __post_init__(self):
        resp = requests.get(self.url, auth=self.auth)
        print(resp)
        page_count = (
            int(resp.headers["x-total-count"]) if "x-total-count" in resp.headers else 1
        )
        self.total_pages = (
            math.ceil(page_count / self.page_size) if page_count > 0 else 1
        )

    @request_retry(5)
    def get(self):
        for page in range(0, self.total_pages):
            response = requests.get(
                self.url,
                auth=self.auth,
                params={"page": page, "page_size": self.page_size, "q": self.query},
            )
            response.raise_for_status()
            yield response
