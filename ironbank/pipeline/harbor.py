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
            page = [page] if isinstance(page, dict) else page
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


# add to pipeline logic
@dataclass
class HarborRobots(Harbor):
    accounts: list = field(default_factory=lambda: [])

    def get_accounts(self, repository: str = "", all: bool = False):
        robots_url = f"{self.api_url}/robots"
        log.info(robots_url)
        paginated_request = PaginatedRequest(self.session, robots_url)
        for page in paginated_request.get():
            print("adding robots")
            if isinstance(page, dict):
                self.accounts.append(
                    HarborRobot(
                        name=page["name"],
                        description=page["description"],
                        expires_at=page["expires_at"],
                    )
                )
            else:
                for account in page:
                    new_account = HarborRobot(
                        name=account["name"], expires_at=account["expires_at"]
                    )
                    if "description" in account.keys():
                        new_account.description = account["description"]
                    self.accounts.append(new_account)


@dataclass
class HarborRobot:
    name: str = ""
    description: str = ""
    expires_at: str = ""


@dataclass
class HarborArtifact(Harbor):
    name: str = ""
    repository: str = ""
    project: str = ""
    digest: str = ""
    tags: list = field(default_factory=lambda: [])
    push_time: str = ""
