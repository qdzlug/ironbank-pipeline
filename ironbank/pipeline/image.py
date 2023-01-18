from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class MissingTagAndDigestError(Exception):
    pass


class MissingNameAndUrlError(Exception):
    pass


@dataclass
class Image:
    """
    The Image Dataclass contains commonly used image attributes

    Either name and tag/digest must be provided or url
    """

    # no registry needed for local paths in docker
    # localhost/ needed for local paths in buildah
    registry: Optional[str] = None
    # name can be excluded if url is present
    name: Optional[str] = None
    digest: Optional[str] = None
    tag: Optional[str] = None
    # url should contain registry, name and tag/digest
    # TODO: pick a better name than url for this purpose
    url: Optional[str] = None
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

    def from_image(self, **kwargs):
        # prioritize passed args
        # TODO: Should work with both self for instance and passed in image
        passed_keys = list(kwargs.keys())

        return Image(
            registry=kwargs["registry"] if "registry" in passed_keys else self.registry,
            name=kwargs["name"] if "name" in passed_keys else self.name,
            digest=kwargs["digest"] if "digest" in passed_keys else self.digest,
            tag=kwargs["tag"] if "tag" in passed_keys else self.tag,
            url=kwargs["url"] if "url" in passed_keys else self.url,
            transport=kwargs["transport"]
            if "transport" in passed_keys
            else self.transport,
        )

    def tag_str(self):
        return f"{self.registry_path}:{self.tag}"

    def digest_str(self):
        return f"{self.registry_path}@{self.digest}"

    def __str__(self):
        # default to tag, else use digest
        if self.url:
            return f"{self.transport}{self.url}"
        elif self.tag:
            return self.tag_str()
        elif self.digest:
            return self.digest_str()


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
