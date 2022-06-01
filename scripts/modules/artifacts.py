import os
import hashlib
import pathlib
from typing import Container
from utils import logger
from dataclasses import dataclass


@dataclass
class _ArtifactBase:
    url: str
    auth: dict = None
    log: logger = logger.setup("Artifact")


@dataclass
class _FileArtifactBase:
    filename: str = None
    validation: dict = None
    dest_path: str = f"{os.environ.get('ARTIFACT_DIR')}/external_resources"

    def __post_init__(self):
        self.artifact_path = pathlib.Path(self.dest_path, self.filename)


@dataclass
class _ContainerArtifactBase:
    tag: str


@dataclass
class Artifact(_ArtifactBase):
    # TODO: consider overriding __new__ to prevent instantiation of this base class
    def delete_artifact(self):
        os.remove(self.artifact_path)
        self.log.error("File deleted")

    # get basic auth, used by Container and Http
    def get_auth(self):
        pass


@dataclass
class FileArtifact(_FileArtifactBase, Artifact):
    def handle_invalid_checksum(self, generated, expected):
        self.log.error(f"Checksum mismatch: generated {generated}, expected {expected}")
        self.delete_artifact()

    def validate_checksum(self):
        if "sha" not in self.validation["type"]:
            raise ValueError(
                f"file verification type not supported: {self.validation['type']}"
            )
        generated_checksum = self.generate_checksum().hexdigest()
        self.log.info(generated_checksum.hexdigest())

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

    def get_auth():
        # do stuff
        pass


@dataclass
class HttpArtifact(FileArtifact):
    log: logger = logger.setup("HttpArtifact")


@dataclass
class ContainerArtifact(Artifact, _ContainerArtifactBase):
    # artifact_path: pathlib.Path = pathlib.Path(f'{os.environ.get('ARTIFACT_DIR')/images/')
    log: logger = logger.setup("ContainerArtifact")
    # TODO: override artifact deletion to remove from registry
    def delete_artifact(self):
        os.remove(pathlib.Path(os.environ.get("ARTIFACT_DIR"), "images", self.tag))
