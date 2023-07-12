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
    """Abstract base class representing a generic artifact.

    This class provides a base for other classes representing specific types of artifacts (like S3, HTTP, etc).
    It provides a common interface and some base functionality (like handling of authentication, deletion of
    artifacts, and basic setup).

    Attributes
    ----------
    url: str
        The URL from where the artifact can be downloaded.
    filename: str
        The filename of the artifact.
    validation: dict
        Dictionary for validation information (e.g., checksum type and value).
    auth: dict
        Dictionary containing authentication details.
    tag: str
        The tag associated with the artifact.
    log: logger
        Logger object for logging.
    dest_path: pathlib.Path
        The path where the artifact should be saved.

    Methods
    -------
    delete_artifact():
        Deletes the artifact file from the local file system.
    get_username_password():
        Decodes the authentication details and returns username and password.
    """

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
        """Delete the artifact file from the local file system.

        Raises
        ------
        FileNotFoundError
            If the file does not exist or is not a file.
        """
        if self.artifact_path.exists() and self.artifact_path.is_file():
            os.remove(self.artifact_path)
            self.log.error(f"File deleted: {self.artifact_path}")

    def get_username_password(self) -> tuple:
        """Retrieves and decodes username and password from environment
        variables.

        Returns
        -------
        tuple
            A tuple containing the decoded username and password.
        """
        credential_id = self.auth["id"].replace("-", "_")
        username = b64decode(os.environ["CREDENTIAL_USERNAME_" + credential_id]).decode(
            "utf-8"
        )
        password = b64decode(os.environ["CREDENTIAL_PASSWORD_" + credential_id]).decode(
            "utf-8"
        )
        return username, password

    @abstractmethod
    def get_credentials(self):
        """Abstract method for getting credentials.

        This method needs to be implemented by any concrete class that inherits from this class.
        The implementation should return the credentials necessary for authorizing operations
        related to the specific type of artifact.

        Returns
        -------
        To be defined by the concrete implementation.

        Raises
        ------
        NotImplementedError
            If the method is not implemented in a concrete subclass.
        """

    @abstractmethod
    def download(self):
        """Abstract method to be overridden in subclasses. This method is
        expected to handle the download process of the artifact.

        Returns
        -------
        To be defined by the concrete implementation.

        Raises
        ------
        NotImplementedError
            If the method is not implemented in a concrete subclass.
        """


@dataclass
class AbstractFileArtifact(AbstractArtifact):
    """An abstract class representing a File Artifact, extending the
    AbstractArtifact base class.

    This class implements additional methods to handle file artifacts, including the
    calculation and validation of file checksums, and validation of file names. These methods
    are implemented based on the requirements of handling file-based artifacts in the system.

    Attributes
    ----------
    Inherits all attributes from the parent class `AbstractArtifact`.

    Methods
    -------
    validate_checksum():
        Validates the checksum of the downloaded file against the expected value.

    generate_checksum():
        Calculates and returns the checksum of the artifact file.

    validate_filename():
        Validates the filename for illegal or unsafe characters.
    """

    def __post_init__(self):
        super().__post_init__()
        self.artifact_path = Path(self.dest_path, self.filename)

    def validate_checksum(self):
        """Validates the checksum of the downloaded file against the expected
        value.

        The checksum is calculated using the method defined in `self.validation["type"]`.
        If this method is not a 'sha' type, a ValueError is raised. The calculated checksum
        is then compared to the expected value in `self.validation["value"]`.

        Raises
        ------
        ValueError:
            If `self.validation["type"]` is not a supported 'sha' hash type.
        AssertionError:
            If the generated checksum does not match `self.validation["value"]`.

        Example
        -------
        >>> artifact = S3Artifact(...)
        >>> artifact.validate_checksum()  # If no exception is raised, the checksum is validated.
        """

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
        """Calculates and returns the checksum of the artifact file.

        The hashing algorithm is determined by `self.validation["type"]`.
        The artifact file is read in 4KB chunks to optimize memory usage.

        Returns
        -------
        hashlib object
            Hash object for the entire file.
        """

        sha_hash = hashlib.new(self.validation["type"])
        with self.artifact_path.open("rb") as f:
            # read file in 4 KB chunks to prevent filling mem unnecessarily
            while chunk := f.read(4096):
                sha_hash.update(chunk)
        return sha_hash

    def validate_filename(self):
        """Validates the filename for illegal or unsafe characters.

        This method uses a regular expression to verify that the filename starts with a
        letter or a number and does not contain any slash or null byte characters.

        Raises
        ------
        ValueError:
            If the filename does not meet the specified criteria, a ValueError is raised with a descriptive message.

        Example
        -------
        >>> artifact = S3Artifact(...)
        >>> artifact.validate_filename()  # Raises ValueError if filename is invalid.
        """
        # Validate filename doesn't do anything nefarious
        re_match = re.search(r"^[A-Za-z0-9][^/\x00]*", self.filename)
        if not re_match:
            raise ValueError(
                "Filename has invalid characters. Filename must start with a letter or a number. Aborting."
            )
