from abc import ABC
from dataclasses import dataclass, field
from urllib.parse import quote_plus

import requests
from requests import Session

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.paginated_request import PaginatedRequest

log: logger = logger.setup("Harbor")


@dataclass
class PayloadString(str):
    pass


@dataclass
class Harbor(ABC):
    """
    An abstract base class representing a connection to a Harbor container registry. 

    Attributes:
        session (requests.Session): A session object used for making HTTP requests.
        api_url (str): The base URL of the Harbor API.
        registry (str): The URL of the Harbor registry.
    """
    session: requests.Session = field(default_factory=Session)
    api_url: str = "https://registry1.dso.mil/api/v2.0"
    registry: str = "registry1.dso.mil"

    def get_robot_accounts(self):
        """
        Retrieve robot accounts associated with this Harbor instance.

        This method should not be called if the Harbor instance does not have a 'robots' attribute.
        The method uses the Harbor API to fetch robot accounts, depending on whether the instance is a HarborSystem or HarborProject.
        """
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
    """
    A class representing the system-level operations in Harbor.

    Attributes:
        robots (list): A list of robots associated with the Harbor system.

    Inherits from:
        Harbor: The parent class representing a connection to Harbor container registry.
    """
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
    """
    A class representing project-level operations in Harbor.

    Attributes:
        name (str): The name of the Harbor project.
        repositories (list): A list of repositories associated with the Harbor project.
        robots (list): A list of robots associated with the Harbor project.

    Inherits from:
        Harbor: The parent class representing a connection to Harbor container registry.
    """
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
    """
    A class representing repository-level operations in Harbor.

    Attributes:
        name (str): The name of the repository in the Harbor project.
        project (str): The project name to which the repository belongs.
        artifacts (list): A list of artifacts associated with the Harbor repository.

    Inherits from:
        Harbor: The parent class representing a connection to Harbor container registry.
    """
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
    """
    A class representing a robot in Harbor, which can be used to perform operations on the Harbor registry.

    Attributes:
        name (str): The name of the robot.
        email (str): The email associated with the robot.
        description (str): The description of the robot.
        expires_at (str): The expiration date of the robot.
        duration (int): The duration of the robot.
        disable (bool): A flag indicating if the robot is disabled.
        level (str): The level of the robot.
        permissions (list[HarborRobotPermissions]): A list of permissions associated with the robot.

    Inherits from:
        Harbor: The parent class representing a connection to Harbor container registry.
    """
    name: str = ""
    email: str = ""
    description: str = ""
    expires_at: str = ""
    duration: int = 365
    disable: bool = False
    level: str = ""
    permissions: list["HarborRobotPermissions"] = field(default_factory=lambda: [])

    def __post_init__(self):
        self.permissions = [
            HarborRobotPermissions(**permission) for permission in self.permissions
        ]

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
        return resp.json()


@dataclass
class HarborRobotPermissions:
    """
    A class representing permissions of a Harbor robot.

    Attributes:
        access (list[dict]): A list of access permissions for the robot.
        kind (str): The kind of the permission.
        namespace (str): The namespace to which the permission is applied.
    """
    access: list[dict] = field(default_factory=lambda: [{}])
    kind: str = ""
    namespace: str = ""


@dataclass
class HarborArtifact:
    """
    A class representing an artifact in a Harbor repository.

    Attributes:
        name (str): The name of the artifact.
        repository (str): The repository in which the artifact is located.
        project (str): The project to which the artifact belongs.
        digest (str): The digest of the artifact.
        tags (list): A list of tags associated with the artifact.
        push_time (str): The time when the artifact was pushed to the repository.
    """
    name: str = ""
    repository: str = ""
    project: str = ""
    digest: str = ""
    tags: list = field(default_factory=lambda: [])
    push_time: str = ""
