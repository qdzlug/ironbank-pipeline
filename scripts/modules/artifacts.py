import os
import re
import hashlib
import pathlib
import subprocess
import requests
from requests.auth import HTTPBasicAuth
from utils import logger
from dataclasses import dataclass
from base64 import b64decode
from typing import Union


@dataclass
class _ArtifactBase:
    # url is optional since urls can also be used for http artifacts
    url: str = None
    auth: dict = None
    log: logger = logger.setup("Artifact")
    dest_path: pathlib.Path = pathlib.Path(f"{os.environ.get('ARTIFACT_DIR')}")
    artifact_path: pathlib.Path = None


@dataclass
class _FileArtifactBase:
    filename: str = None
    validation: dict = None

    def __post_init__(self):
        self.dest_path = pathlib.Path(self.dest_path, "external_resources")
        self.artifact_path = pathlib.Path(self.dest_path, self.filename)


@dataclass
class _ContainerArtifactBase:
    tag: str = None

    def __post_init__(self):
        self.dest_path = pathlib.Path(self.dest_path, "images")
        self.__tar_name = self.tag.replace("/", "-").replace(":", "-")
        self.artifact_path = pathlib.Path(self.dest_path, f"{self.__tar_name}.tar")


@dataclass
class Artifact(_ArtifactBase):
    # TODO: consider overriding __new__ to prevent instantiation of this base class
    def delete_artifact(self):
        os.remove(self.artifact_path)
        self.log.error("File deleted")

    # get basic auth, used by Container and Http
    def get_username_password(self) -> tuple:
        credential_id = self.auth["id"].replace("-", "_")
        username = b64decode(os.environ["CREDENTIAL_USERNAME_" + credential_id]).decode(
            "utf-8"
        )
        password = b64decode(os.environ["CREDENTIAL_PASSWORD_" + credential_id]).decode(
            "utf-8"
        )
        return username, password


@dataclass
class FileArtifact(_FileArtifactBase, Artifact):
    def __post_init__(self):
        super().__post_init__()

    def handle_invalid_checksum(self, generated, expected):
        self.log.error(f"Checksum mismatch: generated {generated}, expected {expected}")
        self.delete_artifact()

    def validate_checksum(self):
        if "sha" not in self.validation["type"]:
            raise ValueError(
                f"file verification type not supported: {self.validation['type']}"
            )
        generated_checksum = self.generate_checksum().hexdigest()
        self.log.info(generated_checksum)

        assert (
            generated_checksum == self.validation["value"]
        ), self.handle_invalid_checksum(generated_checksum, self.validation["value"])
        self.log.info("Checksum validated")

    def generate_checksum(self):
        sha_hash = hashlib.new(self.validation["type"])
        with self.artifact_path.open("rb") as f:
            # read file in 4 KB chunks to prevent filling mem unnecessarily
            while chunk := f.read(4096):
                sha_hash.update(chunk)
        return sha_hash


@dataclass
class S3Artifact(FileArtifact):
    log: logger = logger.setup("S3Artifact")

    def __post_init__(self):
        super().__post_init__()

    # override auth
    def get_username_password(self):
        # do stuff
        credential_id = self.auth["id"].replace("-", "_")
        username = b64decode(os.environ["S3_ACCESS_KEY_" + credential_id]).decode(
            "utf-8"
        )
        password = b64decode(os.environ["S3_SECRET_KEY_" + credential_id]).decode(
            "utf-8"
        )
        region = self.auth["region"]
        return username, password, region


@dataclass
class HttpArtifact(FileArtifact):
    # could also be urls
    urls: list = None
    log: logger = logger.setup("HttpArtifact")

    # schema should prevent url and urls both being defined for a single resource
    # self.urls should have len 1 if url is defined, else it's length should remain the same after this step
    def __post_init__(self):
        super().__post_init__()
        self.urls = self.urls or [self.url]

    def get_credentials(self) -> HTTPBasicAuth:
        username, password = self.get_username_password()
        return HTTPBasicAuth(username, password)

    def download(self) -> Union[int, None]:
        # Validate filename doesn't do anything nefarious
        match = re.search(r"^[A-Za-z0-9][^/\x00]*", self.filename)
        if not match:
            raise ValueError(
                "Filename has invalid characters. Filename must start with a letter or a number. Aborting"
            )
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
                response.raise_for_status()
                if response.status_code == 200:
                    with self.artifact_path.open("wb") as f:
                        f.write(response.content)
                    self.log.info(f"===== ARTIFACTS: {url}")
                    return response.status_code


@dataclass
class ContainerArtifact(Artifact, _ContainerArtifactBase):
    # artifact_path: pathlib.Path = pathlib.Path(f'{os.environ.get('ARTIFACT_DIR')/images/')
    log: logger = logger.setup("ContainerArtifact")
    authfile: pathlib.Path = pathlib.Path("tmp", "prod_auth.json")

    def __post_init__(self):
        super().__post_init__()

    def get_credentials(self) -> str:
        username, password = self.get_username_password()
        return f"{username}:{password}"

    def download(self):
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


@dataclass
class GithubArtifact(ContainerArtifact):
    def __post_init__(self):
        super().__post_init__()

    def get_username_password(self) -> tuple:
        username = b64decode(os.environ["GITHUB_ROBOT_USER"]).decode("utf-8")
        password = b64decode(os.environ["GITHUB_ROBOT_TOKEN"]).decode("utf-8")
        return username, password
