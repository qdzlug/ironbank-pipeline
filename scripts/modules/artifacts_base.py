import os
import pathlib
from utils import logger
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class AbstractArtifact(ABC):
    # url is optional since urls can also be used for http artifacts
    url: str = None
    auth: dict = None
    log: logger = logger.setup("Artifact")
    dest_path: pathlib.Path = pathlib.Path(f"{os.environ.get('ARTIFACT_DIR')}")
    artifact_path: pathlib.Path = None

    @abstractmethod
    def delete_artifact(self):
        pass

    @abstractmethod
    def get_username_password(self):
        pass

    @abstractmethod
    def get_credentials(self):
        pass

    @abstractmethod
    def download(self):
        pass


@dataclass
class AbstractFileArtifact(ABC):
    filename: str = None
    validation: dict = None

    def __post_init__(self):
        self.dest_path = pathlib.Path(self.dest_path, "external_resources")
        self.artifact_path = pathlib.Path(self.dest_path, self.filename)

    @abstractmethod
    def validate_checksum(self):
        pass

    @abstractmethod
    def generate_checksum(self):
        pass

    @abstractmethod
    def validate_filename(self):
        pass


@dataclass
class AbstractContainerArtifact(ABC):
    tag: str = None

    def __post_init__(self):
        self.dest_path = pathlib.Path(self.dest_path, "images")
        self.__tar_name = self.tag.replace("/", "-").replace(":", "-")
        self.artifact_path = pathlib.Path(self.dest_path, f"{self.__tar_name}.tar")
