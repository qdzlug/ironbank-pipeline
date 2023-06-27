import os
from base64 import b64decode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union
from urllib.parse import urlparse

import boto3
import requests
from requests.auth import HTTPBasicAuth

from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.image import Image, ImageFile

from .abstract_artifacts import AbstractArtifact, AbstractFileArtifact
from .utils import logger
from .utils.decorators import request_retry
from .utils.exceptions import InvalidURLList


@dataclass
class S3Artifact(AbstractFileArtifact):
    log: logger = logger.setup("S3Artifact")

    # credentials are just username and password
    def get_credentials(self):
        credential_id = self.auth["id"].replace("-", "_")
        username = b64decode(os.environ["S3_ACCESS_KEY_" + credential_id]).decode(
            "utf-8"
        )
        password = b64decode(os.environ["S3_SECRET_KEY_" + credential_id]).decode(
            "utf-8"
        )
        region = self.auth["region"]
        return username, password, region

    # TODO: Allow parameters to be passed to this function for url, auth etc.
    @request_retry(1)
    def download(self):
        self.validate_filename()
        parsed_url = urlparse(self.url, allow_fragments=False)
        extra_args = {}
        if "versionId" in parsed_url.query:
            extra_args = {
                "VersionId": parsed_url.query.replace("versionId=", "").split("&")[0]
            }
        if not self.auth:
            raise ValueError(
                "You must provide auth to download S3 resources using the s3:// scheme \
                Please use https:// if your S3 bucket is publicly accessible"
            )

        username, password, region = self.get_credentials()

        params = {"aws_access_key_id": username, "aws_secret_access_key": password}

        # TODO: move this to an integration test (using minio)
        # if os.environ.get("LOCALTEST"):
        #     params["endpoint_url"] = "http://localhost:9000"
        #     params["config"] = boto3.session.Config(signature_version="s3v4")
        # else:
        params["region_name"] = region

        self.log.info(f"Downloading from {self.url}")
        s3_client = boto3.client("s3", **params)

        # remove leading forward slash
        bucket, object_name = parsed_url.netloc, parsed_url.path.lstrip("/")

        s3_client.download_file(
            bucket,
            object_name,
            self.artifact_path.as_posix(),
            extra_args,
        )


@dataclass
class HttpArtifact(AbstractFileArtifact):

    """HttpArtifact represents a file artifact available for download via HTTP
    or HTTPS.

    Attributes
    ----------
    urls: list
        List of URLs from which the artifact can be downloaded.
    log: logger
        A logger instance for logging messages during class operation.

    Methods
    -------
    __post_init__():
        Initialization step that sets `urls` attribute. If `urls` is not provided,
        it defaults to a list containing the `url` attribute from the parent class.

    get_credentials() -> HTTPBasicAuth:
        Retrieves the username and password from the authentication information
        and returns an HTTPBasicAuth object for requests authentication.

    download() -> Union[int, None]:
        Downloads the file artifact from the provided URLs. Tries each URL sequentially
        until a successful download (HTTP status code 200). If no URLs are valid,
        raises an InvalidURLList exception.

    Notes
    -----
    * 'log' attribute is initialized with a logger setup for "HttpArtifact".
    * 'download' method retries once on request failure.
    """

    # could also be urls
    urls: list = None
    log: logger = logger.setup("HttpArtifact")

    # schema should prevent url and urls both being defined for a single resource
    # self.urls should have len 1 if url is defined, else it's length should remain the same after this step
    def __post_init__(self):
        super().__post_init__()
        # needs to exist in this post_init because S3 downloads will never have multiple urls
        self.urls = self.urls or [self.url]

    def get_credentials(self) -> HTTPBasicAuth:
        username, password = self.get_username_password()
        return HTTPBasicAuth(username, password)

    # TODO: Allow parameters to be passed to this function for url, auth etc.
    @request_retry(1)
    def download(self) -> Union[int, None]:
        # Validate filename doesn't do anything nefarious
        self.validate_filename()
        # TODO: potentially rethink auth for local dev use
        for url in self.urls:
            self.log.info(f"Downloading from {url}")
            with requests.get(
                url,
                allow_redirects=True,
                stream=True,
                auth=self.get_credentials() if self.auth else None,
            ) as response:
                # exception will be caught in main
                # need unit tests for multiple response statuses
                # skip response.raise_for_status() to prevent raising exception (allow for retry on other urls)
                if response.status_code == 200:
                    with self.artifact_path.open(mode="wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    return response.status_code
        # if we haven't returned at this point, we need to raise an exception
        raise InvalidURLList(
            f"No valid urls provided for {self.filename}. Please ensure the url(s) for this resource exists and is not password protected. If you require basic authentication to download this resource, please open a ticket in this repository."
        )


@dataclass
class ContainerArtifact(AbstractArtifact):

    """ContainerArtifact is a representation of a Docker container image as an
    artifact. This class allows to download and manage Docker images,
    leveraging skopeo tool.

    Attributes
    ----------
    log : logger
        Logger for the class.
    authfile : Path
        Path to the authentication file for Docker.

    Methods
    -------
    __post_init__():
        Overrides the inherited method to setup 'url', '__tar_name', and 'artifact_path'.
    get_credentials() -> str:
        Gets the username and password for authentication.
    download():
        Pulls and stores the Docker image from the specified url.

    Notes
    -----
    The 'log' attribute is set up for "ContainerArtifact".
    If the artifact file already exists when download is called, it will be deleted before downloading again.
    Skopeo tool is used for Docker image operations.
    """

    # artifact_path: Path = Path(f'{os.environ.get('ARTIFACT_DIR')/images/')
    log: logger = logger.setup("ContainerArtifact")
    # the authfile attribute is provided since skopeo can take an authfile but this file isn't created/used in the pipeline
    authfile: Path = field(
        default_factory=lambda: Path(os.environ["DOCKER_AUTH_FILE_PULL"])
    )

    def __post_init__(self):
        super().__post_init__()
        self.url = self.url.replace("docker://", "")
        self.__tar_name = self.tag.replace("/", "-").replace(":", "-")
        self.artifact_path = Path(self.dest_path, f"{self.__tar_name}.tar")

    def get_credentials(self) -> str:
        username, password = self.get_username_password()
        return f"{username}:{password}"

    # TODO: Allow parameters to be passed to this function for url, auth etc.
    @request_retry(3)
    def download(self):
        # prevent failing when running locally due to file already existing
        if self.artifact_path.exists():
            self.log.warning("Found existing container artifact, deleting file")
            self.delete_artifact()

        self.log.info(f"Pulling {self.url}")

        # transport should already be included
        # TODO: check for existing transport
        src = Image(url=self.url, transport="docker://")
        dest = ImageFile(file_path=self.artifact_path, transport="docker-archive:")

        skopeo = Skopeo(authfile=self.authfile)
        skopeo.copy(
            src=src,
            dest=dest,
            remove_signatures=True,
            additional_tags=self.tag,
            src_creds=self.get_credentials() if self.auth else None,
            log_cmd=True,
        )

        self.log.info("Successfully pulled")


@dataclass
class GithubArtifact(ContainerArtifact):

    """GithubArtifact represents a Docker container image as an artifact stored
    on GitHub.

    This class extends the ContainerArtifact class to add GitHub specific functionalities
    such as fetching GitHub authentication credentials.

    Attributes
    ----------
    log : logger
        Logger for the class.

    Methods
    -------
    __post_init__():
        Overrides the inherited method, calling the super() method for initialization.
    get_username_password() -> tuple:
        Gets the GitHub username and token for authentication from environment variables.

    Notes
    -----
    The 'log' attribute is set up for "GithubArtifact".
    GitHub authentication is performed using a robot user, the credentials of which are expected
    to be base64 encoded and stored in the environment variables "GITHUB_ROBOT_USER" and "GITHUB_ROBOT_TOKEN".
    """

    log: logger = logger.setup("GithubArtifact")

    def __post_init__(self):
        super().__post_init__()

    def get_username_password(self) -> tuple:
        username = b64decode(os.environ["GITHUB_ROBOT_USER"]).decode("utf-8")
        password = b64decode(os.environ["GITHUB_ROBOT_TOKEN"]).decode("utf-8")
        return username, password
