from dataclasses import dataclass


class MissingTagAndDigestError(Exception):
    pass


@dataclass
class Image:
    """
    The Image Dataclass contains commonly used image attributes

    At least one of digest or tag must be defined at init
    """

    registry: str
    name: str
    digest: str = None
    tag: str = None
    # skopeo cares about transport (e.g. docker://, container-storage:, etc.)
    # skopeo supported transports: containers-storage, dir, docker, docker-archive, docker-daemon, oci, oci-archive, ostree, tarball
    transport: str = None

    def __post_init__(self):
        # enforce at least one of digest/tag is defined
        # both may be defined
        if not self.digest and not self.tag:
            raise MissingTagAndDigestError
        self.registry_path = f"{self.registry}/{self.name}"

    def tag_str(self):
        return f"{self.registry_path}:{self.tag}"

    def digest_str(self):
        return f"{self.registry_path}@{self.digest}"

    def __str__(self):
        # default to tag, else use digest
        return self.tag_str() if self.tag else self.digest_str()
