import re
import json
import os
from abc import ABC, abstractmethod
from utils import logger
from .types import FileParser, Package
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
import dockerfile

log = logger.setup(name="package_parser", format="| %(levelname)-5s | %(message)s")

from .exceptions import DockerfileParseError


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
        if url.startswith("simple/"):
            return None

        match = re.match(
            r"^packages/(?P<name>[^/]+)/(?P<version>[^/]+)/(?P<filename>[^/]+)\.(?P<ext>tar\.gz|whl|tar\.gz\.asc|whl\.asc)$",
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


# TODO: Move this to a seperate file with other FileParsers
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


# TODO: Move this to a seperate file with other FileParsers
@dataclass
class SbomFileParser(FileParser):
    @classmethod
    def parse(cls, file) -> list[Package]:

        packages: list[Package] = []
        log.info("SBOM parser started")

        data = json.load(file)
        for artifact in data["artifacts"]:

            package = Package(
                kind=artifact["type"],
                name=artifact["name"],
                version=artifact["version"].split(".el")[0],
            )

            if package:
                packages.append(package)
                log.info(f"Parsed package: {package}")

        log.info("File successfully parsed")
        return packages


# TODO: Move this to a seperate file with other FileParsers
@dataclass
class DockerfileParser(FileParser):
    @classmethod
    def parse(cls, filepath) -> None:
        parsed_dockerfile = cls.parse_dockerfile(filepath)
        from_statement_list = cls.remove_non_from_statements(parsed_dockerfile)
        invalid_from = cls.validate_final_from(from_statement_list)
        return invalid_from

    @staticmethod
    def remove_non_from_statements(dockerfile_tuple: tuple) -> list:
        from_list = []
        for command in dockerfile_tuple:
            if command.cmd.lower() == "from":
                from_list.append(command)
        return from_list

    @staticmethod
    def validate_final_from(content: list):
        """
        Returns whether the final FROM statement in the Dockerfile is valid, i.e.
        FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}
        """
        if content[-1].value[0] not in (
            "${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}",
            "$BASE_REGISTRY/$BASE_IMAGE:$BASE_TAG",
        ):
            return True
        else:
            return False

    @staticmethod
    def parse_dockerfile(dockerfile_path: str):
        try:
            parsed_file = dockerfile.parse_file(dockerfile_path)
            return parsed_file
        except dockerfile.GoIOError:
            log.error("The Dockerfile could not be opened.")
            raise DockerfileParseError
        except dockerfile.GoParseError:
            log.error("The Dockerfile is not parseable.")
            raise DockerfileParseError
