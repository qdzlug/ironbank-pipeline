import re
import json
import os
from abc import ABC, abstractmethod
from utils import logger
from .types import FileParser, Package
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from dataclasses import field

log = logger.setup(name="package_parser", format="| %(levelname)-5s | %(message)s")


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
        if url.startswith("simple"):
            return None

        match = re.match(
            r"^/packages/(?P<name>[^/]+)/(?P<version>[^/]+)/(?P<filename>[^/]+)\.(?P<ext>tar\.gz|whl|tar\.gz\.asc|whl\.asc)$",
            url,
        )

        if not match:
            raise ValueError(f"Could not parse pypi URL: {url}")

        return PypiPackage(
            name=match.group("name"), version=match.group("version"), url=url
        )


@dataclass(slots=True, frozen=True)
class NullPackage(ParsedURLPackage):
    @classmethod
    def parse(cls, url) -> None:
        return None


class AccessLogFileParser(FileParser):
    @classmethod
    def parse(cls, file) -> list[Package]:
        repos = json.load(open(os.environ["ACCESS_LOG_REPOS"], "r"))
        packages: list[Package] = []
        # TODO make this an environment variable
        nexus_host = "http://nexus-repository-manager.nexus-repository-manager.svc.cluster.local:8081/repository/"
        nexus_re = re.compile(
            f"({re.escape(nexus_host)})(?P<repo_type>[^/]+)/(?P<url>.*)"
        )

        log.info("Access log parser started")
        access_log = Path(file).open("r")
        log.info("File successfully read")
        line_count = 0

        with access_log:
            for line in access_log.readlines():
                line_count += 1

                line = line.rstrip("\n")

                if not line.startswith("200"):
                    continue

                # split on spaces and get the url
                url = line.split(" ")[-1]

                # match against the nexus repo regex
                re_match = nexus_re.match(url)

                if not re_match:
                    raise ValueError(f"Could not parse URL: {url}")

                repo_type = re_match.group("repo_type")

                # get repository from list
                if repo_type not in repos:
                    raise ValueError(f"Repository type not supported: {repo_type}")

                # call desired parser function
                match repos[repo_type]:
                    case "gosum":
                        package = NullPackage.parse(re_match.group("url"))
                    case "go":
                        package = GoPackage.parse((re_match.group("url")))
                    case "yum":
                        package = YumPackage.parse((re_match.group("url")))
                    case "pypi":
                        package = PypiPackage.parse((re_match.group("url")))

                if package:
                    packages.append(package)
                    log.info(f"Parsed package: {package}")

        log.info("access_log successfully parsed")
        return packages
