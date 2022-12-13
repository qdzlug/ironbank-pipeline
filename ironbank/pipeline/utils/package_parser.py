import re
from abc import ABC, abstractmethod
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.types import Package
from typing import Optional
from dataclasses import dataclass, field

log = logger.setup(name="package_parser")


class ParsedURLPackage(ABC, Package):
    @classmethod
    @abstractmethod
    def parse(cls, url) -> Optional[Package]:
        pass


@dataclass(slots=True, frozen=True)
class YumPackage(ParsedURLPackage):
    kind: str = field(init=False, default="rpm")

    @classmethod
    def parse(cls, url) -> Optional[Package]:
        if url.startswith("repodata"):
            return None

        match = re.match(
            r"(?:^|.+/)(?P<name>[^/]+)-(?P<version>[^/-]*-\d+)\.[^/]+\.[^./]+.rpm",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse yum URL: {url}")

        return YumPackage(
            name=match.group("name"), version=match.group("version"), url=url
        )


@dataclass(slots=True, frozen=True)
class AptPackage(ParsedURLPackage):
    kind: str = field(init=False, default="deb")

    @classmethod
    def parse(cls, url) -> Optional[Package]:
        if url.startswith("dists"):
            return None

        match = re.match(
            r"(?:^|.+\/)(?P<name>[^/]+)_(?P<version>[^/]*)_[^/]+.deb",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse apt URL: {url}")

        return AptPackage(
            name=match.group("name"), version=match.group("version"), url=url
        )


@dataclass(slots=True, frozen=True)
class GoPackage(ParsedURLPackage):
    kind: str = field(init=False, default="go")

    @classmethod
    def parse(cls, url) -> Optional[Package]:
        match = re.match(
            r"(?P<name>.*?)/(:?@v/(?P<version>.*?)\.(?P<ext>[^.]+)|(?P<latest>@latest)|(?P<list>list))$",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse go URL: {url}")
        elif (
            match.group("ext") in ["zip", "info"]
            or match.group("latest")
            or match.group("list")
        ):
            return None
        elif match.group("ext") and match.group("ext") != "mod":
            raise ValueError(f"Unexpected go mod extension: {url}")
        else:
            return GoPackage(
                name=match.group("name"), version=match.group("version"), url=url
            )


@dataclass(slots=True, frozen=True)
class PypiPackage(ParsedURLPackage):
    kind: str = field(init=False, default="python")

    @classmethod
    def parse(cls, url) -> Optional[Package]:
        if url.startswith("simple/"):
            return None

        match = re.match(
            r"^packages/(?P<name>[^/]+)/(?P<version>[^/]+)/(?P<filename>[^/]+)\.(?P<ext>tar\.gz|whl|tar\.gz\.asc|whl\.asc|zip)$",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse pypi URL: {url}")

        return PypiPackage(
            name=match.group("name"), version=match.group("version"), url=url
        )


@dataclass(slots=True, frozen=True)
class NpmPackage(ParsedURLPackage):
    kind: str = field(init=False, default="npm")

    @classmethod
    def parse(cls, url) -> Optional[Package]:
        if "/-/" not in url:
            return None

        match = re.match(
            r"^(?P<name>(?:@[^/]+/)?([^/]+))/-/\2-(?P<version>.*)\.tgz$",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse npm URL: {url}")

        return NpmPackage(
            name=match.group("name"), version=match.group("version"), url=url
        )


@dataclass(slots=True, frozen=True)
class RubyGemPackage(ParsedURLPackage):
    kind: str = field(init=False, default="rubygem")

    @classmethod
    def parse(cls, url) -> Optional[Package]:
        if not url.startswith("gems/"):
            return None

        match = re.match(
            r"^gems/(?P<name>[a-zA-Z0-9._-]+?)-(?P<version>\d[^-]+)(?:-(?:[^-\n]+))*.gem$",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse rubygem URL: {url}")

        return RubyGemPackage(
            name=match.group("name"), version=match.group("version"), url=url
        )


@dataclass(slots=True, frozen=True)
class NullPackage(ParsedURLPackage):
    kind: str = field(init=False, default=None)

    @classmethod
    def parse(cls, url) -> None:
        return None
