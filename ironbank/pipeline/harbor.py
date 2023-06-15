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
    """String for payload."""


@dataclass
class HarborRobot:
    """A class representing a robot in Harbor, which can be used to perform
    operations on the Harbor registry.

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
        HarborApi: The parent class representing a connection to Harbor container registry.
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
        """Initializes the permissions attribute with a list of
        HarborRobotPermissions objects."""
        self.permissions = [
            HarborRobotPermissions(**permission) for permission in self.permissions
        ]

    def payload(self):
        """Formats the HarborRobot instance into a payload dictionary that can
        be used in a HTTP request.

        Returns:
            dict: The HarborRobot instance represented as a dictionary.
        """
        return {
            "name": self.name,
            "description": self.description,
            "duration": self.duration,
            "disable": self.disable,
            "level": self.level,
            "permissions": [permission.__dict__ for permission in self.permissions],
        }


@dataclass
class HarborRobotPermissions:
    """A class representing permissions of a Harbor robot.

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
    """A class representing an artifact in a Harbor repository.

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


@dataclass
class HarborApi(ABC):
    """An abstract base class representing a connection to a Harbor container
    registry.

    Attributes:
        session (requests.Session): A session object used for making HTTP requests.
        api_url (str): The base URL of the Harbor API.
        registry (str): The URL of the Harbor registry.
    """

    session: requests.Session = field(default_factory=Session)
    api_url: str = "https://registry1.dso.mil/api/v2.0"
    registry: str = "registry1.dso.mil"


@dataclass
class HarborRobotsApi(HarborApi):
    """A data class that represents the Robots API for a Harbor instance.

    Attributes:
        robots (list[HarborRobot]): A list of robot accounts associated with the Harbor instance.
            Defaults to an empty list.
    """

    robots: list[HarborRobot] = field(default_factory=lambda: [])

    def get_robot_accounts(self):
        """Retrieve robot accounts associated with this Harbor instance.

        This method should not be called if the Harbor instance does not
        have a 'robots' attribute. The method uses the Harbor API to
        fetch robot accounts, depending on whether the instance is a
        HarborSystem or HarborProjectApi.
        """
        assert getattr(self, "robots", "not_defined") != "not_defined"
        if isinstance(self, HarborSystemApi):
            robots_url = f"{self.api_url}/robots"
        elif isinstance(self, HarborProjectApi):
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

    def create_robot(self, robot: HarborRobot):
        """Creates a robot account in Harbor with the attributes of the
        HarborRobot instance.

        Returns:
            dict: The response from the Harbor API.
        """
        robot_url = f"{self.api_url}/robots"
        resp = self.session.post(
            robot_url,
            json=robot.payload(),
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()


@dataclass
class HarborRepositoryApi(HarborApi):
    """A class representing repository-level operations in Harbor.

    Attributes:
        name (str): The name of the repository in the Harbor project.
        project (str): The project name to which the repository belongs.
        artifacts (list): A list of artifacts associated with the Harbor repository.

    Inherits from:
        HarborApi: The parent class representing a connection to Harbor container registry.
    """

    name: str = ""
    project: str = ""
    artifacts: list = field(default_factory=lambda: [])

    def get_repository_artifact(self, reference: str = "", all_artifacts: bool = False):
        """Fetches and stores a specific artifact or all artifacts in a Harbor
        repository.

        Args:
            reference (str, optional): The specific artifact to fetch. Defaults to "".
            all (bool, optional): If True, fetches all artifacts. Defaults to False.

        This method sets the artifacts attribute with a list of HarborArtifact objects.
        """
        artifact_url = f"{self.api_url}/projects/{self.project}/repositories/{quote_plus(self.name)}/artifacts/{reference}"
        if all_artifacts:
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
class HarborProjectApi(HarborRobotsApi):
    """A class representing project-level operations in Harbor.

    Attributes:
        name (str): The name of the Harbor project.
        repositories (list): A list of repositories associated with the Harbor project.
        robots (list): A list of robots associated with the Harbor project.

    Inherits from:
        HarborRobotsApi: The parent class representing a connection to Harbor container registry with support for gathering robots for the dependent api's context.
    """

    name: str = ""
    repositories: list[HarborRepositoryApi] = field(default_factory=lambda: [])
    robots_url: str = field(init=False)

    def __post_init__(self):
        self.robots_url = f"{self.api_url}/projects/{quote_plus(self.name)}/robots"

    def get_project_repository(self, repository: str = "", all_repos: bool = False):
        """Fetches and stores a specific repository or all repositories in a
        Harbor project.

        Args:
            repository (str, optional): The name of the specific repository to fetch. Defaults to "".
            all (bool, optional): If True, fetches all repositories. Defaults to False.

        This method sets the repositories attribute with a list of HarborRepositoryApi objects.
        """
        repository_url = (
            f"{self.api_url}/projects/{self.name}/repositories/{quote_plus(repository)}"
        )
        if all_repos:
            repository_url = f"{self.api_url}/projects/{self.name}/repositories"
        paginated_request = PaginatedRequest(self.session, repository_url)
        for page in paginated_request.get():
            for item in [page] if isinstance(page, dict) else page:
                self.repositories.append(
                    HarborRepositoryApi(
                        name="/".join(item["name"].split("/")[1:]),
                        project=self.name,
                    )
                )


@dataclass
class HarborSystemApi(HarborRobotsApi):
    """A class representing the system-level operations in Harbor.

    Attributes:
        robots (list): A list of robots associated with the Harbor system.

    Inherits from:
        HarborRobotsApi: The parent class representing a connection to Harbor container registry with support for gathering robots for the dependent api's context.
    """

    projects: list[HarborProjectApi] = field(default_factory=lambda: [])
    robots_urls: str = field(init=False)

    def __post_init__(self):
        self.robots_url = f"{self.api_url}/robots"

    def get_projects(self):
        """Fetches and stores all the projects in the Harbor system.

        This method sets the projects attribute with a list of
        HarborProjectApi objects.
        """
        self.projects = []
        project_url = f"{self.api_url}/projects"
        paginated_request = PaginatedRequest(self.session, project_url)
        for page in paginated_request.get():
            for item in [page] if isinstance(page, dict) else page:
                self.projects.append(
                    HarborProjectApi(
                        session=self.session,
                        name=item["name"],
                    )
                )
