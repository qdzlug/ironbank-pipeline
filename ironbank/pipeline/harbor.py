import requests
import json
from dataclasses import dataclass, field
from ironbank.pipeline.utils import logger
from abc import ABC
from urllib.parse import quote_plus
from requests import Session
from ironbank.pipeline.utils.paginated_request import PaginatedRequest

log: logger = logger.setup("Harbor")


@dataclass
class PayloadString(str):
    pass


@dataclass
class Harbor(ABC):
    session: requests.Session = field(default_factory=lambda: Session())
    api_url: str = "https://registry1.dso.mil/api/v2.0"
    registry: str = "registry1.dso.mil"

    def get_robot_accounts(self):
        # Don't call this method for Harbor Classes without a robots attribute
        assert getattr(self, "robots", "not_defined") != "not_defined"
        if isinstance(self, HarborSystem):
            robots_url = f"{self.api_url}/robots"
        elif isinstance(self, HarborProject):
            robots_url = f"{self.api_url}/projects/{quote_plus(self.name)}/robots"
        else:
            return
        paginated_request = PaginatedRequest(self.session, robots_url)
        for page in paginated_request.get():
            for item in [page] if isinstance(page, dict) else page:
                self.robots.append(
                    HarborRobot(
                        name=item["name"],
                        description=item["description"]
                        if "description" in item
                        else "",
                        expires_at=item["expires_at"],
                    )
                )


@dataclass
class HarborSystem(Harbor):
    robots: list = field(default_factory=lambda: [])

    def get_projects(self):
        self.projects = []
        project_url = f"{self.api_url}/projects"
        paginated_request = PaginatedRequest(self.session, project_url)
        for page in paginated_request.get():
            for item in [page] if isinstance(page, dict) else page:
                self.projects.append(
                    HarborProject(
                        session=self.session,
                        name=item["name"],
                    )
                )


@dataclass
class HarborProject(Harbor):
    name: str = ""
    repositories: list = field(default_factory=lambda: [])
    robots: list = field(default_factory=lambda: [])

    def get_project_repository(self, repository: str = "", all: bool = False):
        repository_url = (
            f"{self.api_url}/projects/{self.name}/repositories/{quote_plus(repository)}"
        )
        if all:
            repository_url = f"{self.api_url}/projects/{self.name}/repositories"
        paginated_request = PaginatedRequest(self.session, repository_url)
        for page in paginated_request.get():
            for item in [page] if isinstance(page, dict) else page:
                self.repositories.append(
                    HarborRepository(
                        name="/".join(item["name"].split("/")[1:]),
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
            for item in [page] if isinstance(page, dict) else page:
                self.artifacts.append(
                    HarborArtifact(
                        digest=item["digest"],
                        tags=item["tags"] if "tags" in item else None,
                        project=self.project,
                        repository=self.name,
                        push_time=item["push_time"],
                    )
                )


@dataclass
class HarborRobot(Harbor):
    name: str = ""
    description: str = ""
    expires_at: str = ""
    duration: int = 365
    disable: bool = False
    level: str = ""
    permissions: list["HarborRobotPermissions"] = field(default_factory=lambda: [])

    def __post_init__(self):
        self.permissions = [HarborRobotPermissions(**permission) for permission in self.permissions]

    def payload(self):
        return {
            "name": self.name,
            "description": self.description,
            "duration": self.duration,
            "disable": self.disable,
            "level": self.level,
            "permissions": [permission.__dict__ for permission in self.permissions],
        }

    def create_robot(self):
        robot_url = f"{self.api_url}/robots"
        resp = self.session.post(
            robot_url,
            json=self.payload(),
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()


@dataclass
class HarborRobotPermissions:
    access: list[dict] = field(default_factory=lambda: [{}])
    kind: str = ""
    namespace: str = ""


@dataclass
class HarborArtifact:
    name: str = ""
    repository: str = ""
    project: str = ""
    digest: str = ""
    tags: list = field(default_factory=lambda: [])
    push_time: str = ""
