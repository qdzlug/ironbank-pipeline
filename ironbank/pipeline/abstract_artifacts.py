import hashlib
import os
from pathlib import Path
import re
from abc import ABC, abstractmethod
from base64 import b64decode
from dataclasses import dataclass

from .utils import logger


@dataclass
class AbstractArtifact(ABC):
    url: str = None
    filename: str = None
    validation: dict = None
    auth: dict = None
    tag: str = None
    log: logger = logger.setup("Artifact")
    dest_path: Path = None

    def __post_init__(self):
        self.dest_path = self.dest_path or Path(f"{os.environ.get('ARTIFACT_DIR')}")
        self.artifact_path = Path(self.dest_path, self.filename or self.tag)

    def delete_artifact(self):
        if self.artifact_path.exists() and self.artifact_path.is_file():
            os.remove(self.artifact_path)
            self.log.error(f"File deleted: {self.artifact_path}")

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

    @abstractmethod
    def get_credentials():
        pass

    @abstractmethod
    def download():
        pass


@dataclass
class AbstractFileArtifact(AbstractArtifact):
    def __post_init__(self):
        super().__post_init__()
        self.artifact_path = Path(self.dest_path, self.filename)

    def validate_checksum(self):
        if "sha" not in self.validation["type"]:
            raise ValueError(
                f"file verification type not supported: {self.validation['type']}"
            )
        generated_checksum = self.generate_checksum().hexdigest()
        self.log.info(generated_checksum)

        assert (
            generated_checksum == self.validation["value"]
        ), f"Checksum mismatch: generated {generated_checksum}, expected {self.validation['value']}"
        self.log.info("Checksum validated")

    def generate_checksum(self):
        sha_hash = hashlib.new(self.validation["type"])
        with self.artifact_path.open("rb") as f:
            # read file in 4 KB chunks to prevent filling mem unnecessarily
            while chunk := f.read(4096):
                sha_hash.update(chunk)
        return sha_hash

    def validate_filename(self):
        # Validate filename doesn't do anything nefarious
        re_match = re.search(r"^[A-Za-z0-9][^/\x00]*", self.filename)
        if not re_match:
            raise ValueError(
                "Filename has invalid characters. Filename must start with a letter or a number. Aborting."
            )
