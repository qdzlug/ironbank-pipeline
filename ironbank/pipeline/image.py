from dataclasses import dataclass
from pathlib import Path


class MissingTagAndDigestError(Exception):
    pass


@dataclass
class Image:
    """
    The Image Dataclass contains commonly used image attributes

    At least one of digest or tag must be defined at init
    """

    name: str
    # no registry needed for local paths
    registry: str = None
    digest: str = None
    tag: str = None
    # skopeo cares about transport (e.g. docker://, container-storage:, etc.)
    # skopeo supported transports: containers-storage, dir, docker, docker-archive, docker-daemon, oci, oci-archive, ostree, tarball
    transport: str = ""

    def __post_init__(self):
        # enforce at least one of digest/tag is defined
        # both may be defined
        if not self.digest and not self.tag:
            raise MissingTagAndDigestError
        self.registry_path = (
            f"{self.registry}/{self.name}" if self.registry else self.name
        )

    def tag_str(self):
        # TODO: potentially move the transport formatting to skopeo, since it's the only tool that cares about transport
        return f"{self.transport}{self.registry_path}:{self.tag}"

    def digest_str(self):
        # TODO: potentially move the transport formatting to skopeo, since it's the only tool that cares about transport
        return f"{self.transport}{self.registry_path}@{self.digest}"

    def __str__(self):
        # default to tag, else use digest
        return self.tag_str() if self.tag else self.digest_str()


@dataclass
class ImageFile:
    file_path: Path | str
    # skopeo cares about transport (e.g. docker://, container-storage:, etc.)
    # skopeo supported transports: containers-storage, dir, docker, docker-archive, docker-daemon, oci, oci-archive, ostree, tarball
    transport: str = ""

    def __post_init__(self):
        self.file_path = (
            Path(self.file_path)
            if not isinstance(self.file_path, Path)
            else self.file_path
        )

    def __str__(self):
        # TODO: potentially move the transport formatting to skopeo, since it's the only tool that cares about transport
        return f"{self.transport}{self.file_path}"
