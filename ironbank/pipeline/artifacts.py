import os
import pathlib
import subprocess
import requests
import boto3
from urllib.parse import urlparse
from requests.auth import HTTPBasicAuth
from .utils import logger
from dataclasses import dataclass
from base64 import b64decode
from typing import Union
from .utils.decorators import request_retry
from .utils.exceptions import InvalidURLList, ORASDownloadError
from .abstract_artifacts import (
    AbstractArtifact,
    AbstractFileArtifact,
)


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
                    self.artifact_path.write_bytes(response.content)
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
        self.dest_path = pathlib.Path(self.dest_path, "images")
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
        pull_cmd = [
            "skopeo",
            "copy",
        ]
        # authfile may not exist when testing locally
        pull_cmd += [f"--authfile={self.authfile}"] if self.authfile.exists() else []
        pull_cmd += ["--remove-signatures", "--additional-tag", self.tag]
        pull_cmd += ["--src-creds", self.get_credentials()] if self.auth else []
        # add src and dest
        pull_cmd += [self.url, f"docker-archive:{self.artifact_path}"]
        subprocess.run(
            args=pull_cmd,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            check=True,
        )
        self.log.info("Successfully pulled")


@dataclass
class ORASArtifact(AbstractArtifact):
    log: logger = logger.setup("ORASArtifact")

    def __post_init__(self):
        pass

    def get_credentials(self) -> None:
        pass

    @classmethod
    def find_sbom(cls, img_path: str, docker_config_dir: str) -> str:
        triangulate_cmd = [
            "cosign",
            "triangulate",
            "--type",
            "sbom",
            f"{img_path}",
        ]
        cls.log.info(triangulate_cmd)
        try:
            sbom = subprocess.run(
                triangulate_cmd,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                check=True,
                env={
                    "PATH": os.environ["PATH"],
                    "DOCKER_CONFIG": docker_config_dir,
                },
            )
            return sbom.stdout
        except subprocess.SubprocessError:
            raise ORASDownloadError(
                f"Cosign Triangulate Failed | Could not locate SBOM for {img_path}"
            )

    @classmethod
    def verify(cls, sbom: str, docker_config_dir: str):
        try:
            cert = pathlib.Path(
                os.environ.get("PIPELINE_REPO_DIR"),
                "scripts",
                "cosign",
                "cosign-certificate.pem",
            )
            if not cert.is_file():
                raise FileNotFoundError

            verify_cmd = [
                "cosign",
                "verify",
                "--cert",
                cert.as_posix(),
                sbom,
            ]
            cls.log.info(verify_cmd)
            subprocess.run(
                verify_cmd,
                encoding="utf-8",
                check=True,
                env={
                    "PATH": os.environ["PATH"],
                    "DOCKER_CONFIG": docker_config_dir,
                },
            )
        except subprocess.SubprocessError:
            raise ORASDownloadError(
                f"Cosign Verify Failed | Could not verify signature for {sbom}"
            )
        except FileNotFoundError:
            raise ORASDownloadError(
                f"Cosign Verify Failed | Could not find cert file: {cert}"
            )

    @classmethod
    @request_retry(3)
    def download(cls, img_path: str, output_dir: str, docker_config_dir: str):
        sbom = cls.find_sbom(img_path, docker_config_dir).strip()

        cls.verify(sbom, docker_config_dir)

        pull_cmd = [
            "oras",
            "pull",
            "--allow-all",
            sbom,
        ]
        cls.log.info(pull_cmd)

        try:
            subprocess.run(
                pull_cmd,
                encoding="utf-8",
                check=True,
                cwd=output_dir,
                env={
                    "PATH": os.environ["PATH"],
                    "DOCKER_CONFIG": docker_config_dir,
                },
            )
        except subprocess.SubprocessError:
            raise ORASDownloadError("Could not ORAS pull.")


@dataclass
class GithubArtifact(ContainerArtifact):
    log: logger = logger.setup("GithubArtifact")

    def __post_init__(self):
        super().__post_init__()

    def get_username_password(self) -> tuple:
        username = b64decode(os.environ["GITHUB_ROBOT_USER"]).decode("utf-8")
        password = b64decode(os.environ["GITHUB_ROBOT_TOKEN"]).decode("utf-8")
        return username, password
