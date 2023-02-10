import requests
from dataclasses import dataclass, field
from ironbank.pipeline.utils import logger
from abc import ABC
from urllib.parse import quote_plus
from .utils.paginated_request import PaginatedRequest

log: logger = logger.setup("Harbor")


@dataclass
class Harbor(ABC):
    auth: tuple
    host: str = "https://registry1.dso.mil"
    registry: str = "registry1.dso.mil"

    def __post_init__(self):
        self.api_url = f"{self.host}/api/v2.0"


@dataclass
class HarborProject(Harbor):
    name: str = ""
    repositories: list = field(default_factory=lambda: [])

    def __post_init__(self):
        super().__post_init__()

    def get_project_repository(self, repository: str = "", all: bool = False):
        repository_url = (
            f"{self.api_url}/projects/{self.name}/repositories/{quote_plus(repository)}"
        )
        if all:
            repository_url = f"{self.api_url}/projects/{self.name}/repositories"
        paginated_request = PaginatedRequest(self.auth, repository_url)
        try:
            for page in paginated_request.get():
                if isinstance(page.json(), dict):
                    self.repositories.append(
                        HarborRepository(
                            self.auth, name='/'.join(page.json()["name"].split('/')[1:]), project=self.name
                        )
                    )
                else:
                    for repository in page.json():
                        self.repositories.append(
                            HarborRepository(
                                self.auth, name='/'.join(repository["name"].split('/')[1:]), project=self.name
                            )
                        )

        except requests.exceptions.HTTPError as re:
            log.info("Error while retrieving Harbor project %s", self.name)
            raise re


@dataclass
class HarborRepository(Harbor):
    name: str = ""
    project: str = ""
    artifacts: list = field(default_factory=lambda: [])

    def __post_init__(self):
        super().__post_init__()

    def get_repository_artifact(self, reference: str = "", all: bool = False):
        artifact_url = f"{self.api_url}/projects/{self.project}/repositories/{quote_plus(self.name)}/artifacts/{reference}"
        if all:
            artifact_url = f"{self.api_url}/projects/{self.project}/repositories/{quote_plus(self.name)}/artifacts"
        paginated_request = PaginatedRequest(self.auth, artifact_url)
        try:
            for page in paginated_request.get():
                if isinstance(page.json(), dict):
                    self.artifacts.append(
                        HarborArtifact(
                            auth=self.auth,
                            digest=artifact["digest"],
                            tags=page.json()["tags"],
                            project=self.project,
                            repository=self.name,
                            push_time=artifact["push_time"]
                        )
                    )
                else:
                    for artifact in page.json():
                        self.artifacts.append(
                            HarborArtifact(
                                auth=self.auth,
                                digest=artifact["digest"],
                                tags=artifact["tags"],
                                project=self.project,
                                repository=self.name,
                                push_time=artifact["push_time"]
                            )
                        )

        except requests.exceptions.HTTPError as re:
            log.info("Error while retrieving Harbor repository %s artifacts", self.name)
            raise re


@dataclass
class HarborArtifact(Harbor):
    name: str = ""
    repository: str = ""
    project: str = ""
    digest: str = ""
    tags: list = field(default_factory=lambda: [])
    push_time: str = ""

    # def __post_init__(self):
    #     super().__post_init__()
    #
    # def get_artifact_tags(self, tag: str = "", all: bool = False):
    #     tag_url = "{self.api_url}/projects/{self.project}/repositories/{quote_plus(self.repository)}/artifacts/{quote_plus(self.name)}/tags/{tag}"
    #     if all:
    #         tag_url = "{self.api_url}/projects/{self.project}/repositories/{quote_plus(self.repository)}/artifacts/{quote_plus(self.name)}/tags"
    #     paginated_request = PaginatedRequest(self.auth, tag_url)
    #     try:
    #         for page in paginated_request.get():
    #             for tag in page.json():
    #                 self.tags.append(tag)
    #     except requests.exceptions.HTTPError as re:
    #         log.info(
    #             "Error while retrieving Harbor artifact %s details from repository %s",
    #             self.name,
    #             self.repository,
    #         )
    #         raise re
