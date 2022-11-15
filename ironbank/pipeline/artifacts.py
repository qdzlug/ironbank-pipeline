import json
import os
import pathlib
import subprocess
import requests
import boto3
from urllib.parse import urlparse
from requests.auth import HTTPBasicAuth
from .utils import logger
from dataclasses import dataclass, field
from base64 import b64decode
from typing import Union
from .utils.decorators import request_retry
from .utils.exceptions import InvalidURLList, CosignDownloadError
from .abstract_artifacts import (
    AbstractArtifact,
    AbstractFileArtifact,
)
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.utils.predicates import get_predicate_files


@dataclass
class S3Artifact(AbstractFileArtifact):
    log: logger = logger.setup("S3Artifact")

    def __post_init__(self):
        super().__post_init__()

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
    # artifact_path: pathlib.Path = pathlib.Path(f'{os.environ.get('ARTIFACT_DIR')/images/')
    log: logger = logger.setup("ContainerArtifact")
    authfile: pathlib.Path = pathlib.Path("tmp", "prod_auth.json")

    def __post_init__(self):
        super().__post_init__()
        self.url = self.url.replace("docker://", "")
        self.__tar_name = self.tag.replace("/", "-").replace(":", "-")
        self.artifact_path = pathlib.Path(self.dest_path, f"{self.__tar_name}.tar")

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
class CosignArtifact(AbstractArtifact):
    log: logger = logger.setup("CosignArtifact")
    predicate_files: dict = field(default_factory=get_predicate_files)

    def __post_init__(self):
        pass

    def get_credentials(self) -> None:
        pass

    @classmethod
    @request_retry(3)
    def download(
        cls, image: Image, output_dir: str, docker_config_dir: str, predicate_type: str
    ):
        # predicate types/files can be found in ironbank/pipeline/utils/predicates.py

        pull_cmd = [
            "cosign",
            "download",
            "attestation",
            str(image),
        ]
        cls.log.info(pull_cmd)

        try:
            proc = subprocess.Popen(
                pull_cmd,
                encoding="utf-8",
                # check=True,
                cwd=output_dir,
                env={
                    "PATH": os.environ["PATH"],
                    "DOCKER_CONFIG": docker_config_dir,
                },
            )
            for line in iter(proc.stdout.readline, ""):
                payload = json.loads(line.decode())["payload"]
                predicate = json.loads(b64decode(payload))
                # payload can take up a lot of memory, delete after decoding and converting to dict object
                del payload
                if predicate["predicateType"] == predicate_type:
                    with pathlib.Path(cls.predicate_files[predicate_type]).open(
                        "w+"
                    ) as f:
                        json.dump(predicate["predicate"], f, indent=4)
                    if proc.poll() is not None:
                        break

        except subprocess.SubprocessError:
            raise CosignDownloadError("Could not ORAS pull.")


@dataclass
class GithubArtifact(ContainerArtifact):
    log: logger = logger.setup("GithubArtifact")

    def __post_init__(self):
        super().__post_init__()

    def get_username_password(self) -> tuple:
        username = b64decode(os.environ["GITHUB_ROBOT_USER"]).decode("utf-8")
        password = b64decode(os.environ["GITHUB_ROBOT_TOKEN"]).decode("utf-8")
        return username, password
