import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.types import Package

log = logger.setup(name="package_parser")


class ParsedURLPackage(ABC, Package):  # pylint: disable=R0903
    """This is an abstract base class for different types of packages that can
    be parsed from a URL.

    The abstract method
    `parse` must be implemented in any class that inherits from this one.
    """

    @classmethod
    @abstractmethod
    def parse(cls, url) -> Optional[Package]:
        """Abstract parse method."""


@dataclass(slots=True, frozen=True)
class RpmPackage(ParsedURLPackage):
    """This class represents an RPM package and includes a method to parse an
    RPM package from a URL."""

    kind: str = field(init=False, default="rpm")

    @classmethod
    def parse(cls, url) -> Optional[Package]:
        if url.startswith("repodata") or url.startswith("media"):
            return None

        match = re.match(
            r"(?:^|.+/)(?P<name>[^/]+)-(?P<version>[^/-]*-\d.*)(?:.rpm)*.rpm$",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse yum URL: {url}")

        return cls(name=match.group("name"), version=match.group("version"), url=url)


@dataclass(slots=True, frozen=True)
class ApkPackage(ParsedURLPackage):
    """This class represents an APK package and includes a method to parse an
    APK package from a URL."""

    kind: str = field(init=False, default="apk")

    @classmethod
    def parse(cls, url) -> Optional[Package]:
        if "APKINDEX" in url:
            return None

        match = re.match(
            r"(?:^|.+/)(?P<name>[^/]+)-(?P<version>[0-9][^/]*(-[a-z][0-9]+)?).apk",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse apk URL: {url}")

        return cls(name=match.group("name"), version=match.group("version"), url=url)


@dataclass(slots=True, frozen=True)
class DebianPackage(ParsedURLPackage):
    """This class represents a Debian package and includes a method to parse a
    Debian package from a URL."""

    kind: str = field(init=False, default="deb")

    @classmethod
    def parse(cls, url) -> Optional[Package]:
        if url.startswith("dists"):
            return None

        match = re.match(
            r"(?:^|.+/)(?P<name>[^/_]+)(?:_)?(?P<version>\d+.*)(?:.deb)*.deb$",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse deb URL: {url}")

        return cls(name=match.group("name"), version=match.group("version"), url=url)


@dataclass(slots=True, frozen=True)
class GoPackage(ParsedURLPackage):
    """This class represents a Go package and includes a method to parse a Go
    package from a URL."""

    kind: str = field(init=False, default="go")

    @classmethod
    def parse(cls, url) -> Optional[Package]:
        match = re.match(
            r"(?P<name>.*?)/(:?@v/(?P<version>.*?)\.(?P<ext>[^.]+)|(?P<latest>@latest)|(?P<list>list))$",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse go URL: {url}")
        if (
            match.group("ext") in ["zip", "info"]
            or match.group("latest")
            or match.group("list")
        ):
            return None
        if match.group("ext") and match.group("ext") != "mod":
            raise ValueError(f"Unexpected go mod extension: {url}")
        return cls(name=match.group("name"), version=match.group("version"), url=url)


@dataclass(slots=True, frozen=True)
class PypiPackage(ParsedURLPackage):
    """This class represents a PyPi package and includes a method to parse a
    PyPi package from a URL."""

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

        return cls(name=match.group("name"), version=match.group("version"), url=url)


@dataclass(slots=True, frozen=True)
class NpmPackage(ParsedURLPackage):
    """This class represents an NPM package and includes a method to parse an
    NPM package from a URL."""

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

        return cls(name=match.group("name"), version=match.group("version"), url=url)


@dataclass(slots=True, frozen=True)
class RubyGemPackage(ParsedURLPackage):
    """This class represents a RubyGem package and includes a method to parse a
    RubyGem package from a URL."""

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

        return cls(name=match.group("name"), version=match.group("version"), url=url)


@dataclass(slots=True, frozen=True)
class NullPackage(ParsedURLPackage):
    """This class represents a null package and includes a method to parse a
    null package from a URL.

    Parsing a null package always returns None.
    """

    kind: str = field(init=False, default=None)

    @classmethod
    def parse(cls, url) -> None:
        return None
