import requests
from dataclasses import dataclass, field
from ironbank.pipeline.utils import logger
from abc import ABC
from urllib.parse import quote_plus
from ironbank.pipeline.utils.paginated_request import PaginatedRequest

log: logger = logger.setup("Harbor")


@dataclass
class Harbor(ABC):
    session: requests.Session
    api_url: str = "https://registry1.dso.mil/api/v2.0"
    registry: str = "registry1.dso.mil"


@dataclass
class HarborProject(Harbor):
    name: str = ""
    repositories: list = field(default_factory=lambda: [])

    def get_project_repository(self, repository: str = "", all: bool = False):
        repository_url = (
            f"{self.api_url}/projects/{self.name}/repositories/{quote_plus(repository)}"
        )
        if all:
            repository_url = f"{self.api_url}/projects/{self.name}/repositories"
        paginated_request = PaginatedRequest(self.session, repository_url)
        for page in paginated_request.get():
            print("adding repositories")
            if isinstance(page, dict):
                self.repositories.append(
                    HarborRepository(
                        session=self.session,
                        name="/".join(page["name"].split("/")[1:]),
                        project=self.name,
                    )
                )
            else:
                for repository in page:
                    self.repositories.append(
                        HarborRepository(
                            session=self.session,
                            name="/".join(repository["name"].split("/")[1:]),
                            project=self.name,
                        )
                    )


@dataclass
class HarborRepository(Harbor):
    name: str = ""
    project: str = ""
    artifacts: list = field(default_factory=lambda: [])

    def get_repository_artifact(self, reference: str = "", all: bool = False):
        artifact_url = f"{self.api_url}/projects/{self.project}/repositories/{quote_plus(self.name)}/artifacts/{reference}"
        if all:
            artifact_url = f"{self.api_url}/projects/{self.project}/repositories/{quote_plus(self.name)}/artifacts"
        paginated_request = PaginatedRequest(self.session, artifact_url)
        for page in paginated_request.get():
            page = [page] if isinstance(page, dict) else page
            for artifact in page:
                self.artifacts.append(
                    HarborArtifact(
                        session=self.session,
                        digest=artifact["digest"],
                        tags=artifact["tags"] if "tags" in artifact else None,
                        project=self.project,
                        repository=self.name,
                        push_time=artifact["push_time"],
                    )
                )


@dataclass
class HarborArtifact(Harbor):
    name: str = ""
    repository: str = ""
    project: str = ""
    digest: str = ""
    tags: list = field(default_factory=lambda: [])
    push_time: str = ""
