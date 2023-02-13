import requests
import math

from dataclasses import dataclass
from .request_retry import request_retry

@dataclass
class PaginatedRequest:
    session: requests.Session
    url: str
    query: str = ""
    page: int = 1
    page_size: int = 100

    @request_retry(5)
    def __post_init__(self):
        resp = self.session.get(self.url)
        resp.raise_for_status()
        page_count = (
            int(resp.headers["x-total-count"]) if "x-total-count" in resp.headers else 1
        )
        self.total_pages = math.ceil(page_count / self.page_size) if page_count > 0 else 1
    @request_retry(5)
    def get(self):
        for page in range(0, self.total_pages):
            try:
              response = self.session.get(
                  self.url,
                  params={"page": page, "page_size": self.page_size, "q": self.query},
              )
              response.raise_for_status()
            except requests.HTTPError as re:
                raise re
            yield response.json()
