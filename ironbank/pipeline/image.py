from dataclasses import dataclass
from pathlib import Path


class MissingTagAndDigestError(Exception):
    pass


class MissingNameAndUrlError(Exception):
    pass


@dataclass
class Image:
    """
    The Image Dataclass contains commonly used image attributes

    At least one of digest or tag must be defined at init
    """

    # no registry needed for local paths
    registry: str = None
    # name can be excluded if url is present
    name: str = None
    digest: str = None
    tag: str = None
    # url should contain registry, name and tag/digest
    # TODO: pick a better name than url for this purpose
    url: str = None
    # skopeo cares about transport (e.g. docker://, container-storage:, etc.)
    # skopeo supported transports: containers-storage, dir, docker, docker-archive, docker-daemon, oci, oci-archive, ostree, tarball
    transport: str = ""

    def __post_init__(self):
        # enforce at least one of digest/tag is defined
        # both may be defined
        if self.name:
            if not self.digest and not self.tag:
                raise MissingTagAndDigestError(
                    "Missing tag and digest for Image type with name defined"
                )
        elif not self.url:
            raise MissingNameAndUrlError(
                "Missing name and url for Image type. One must be provided at instantiation"
            )
        self.registry_path = (
            f"{self.registry}/{self.name}" if self.registry else self.name
        )

    @classmethod
    def from_image(cls, image, **kwargs):
        # prioritize passed args
        # TODO: Should work with both self for instance and passed in image
        return Image(
            registry=kwargs.get("registry") or image.registry,
            name=kwargs.get("name") or image.name,
            digest=kwargs.get("digest") or image.digest,
            tag=kwargs.get("tag") or image.tag,
            url=kwargs.get("url") or image.url,
            transport=kwargs.get("transport") or image.transport,
        )

    def tag_str(self):
        # TODO: potentially move the transport formatting to skopeo, since it's the only tool that cares about transport
        return f"{self.transport}{self.registry_path}:{self.tag}"

    def digest_str(self):
        # TODO: potentially move the transport formatting to skopeo, since it's the only tool that cares about transport
        return f"{self.transport}{self.registry_path}@{self.digest}"

    def __str__(self):
        # default to tag, else use digest
        if self.url:
            return f"{self.transport}{self.url}"
        elif self.tag:
            return self.tag_str()
        elif self.digest:
            return self.digest_str()
        else:
            return None


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
