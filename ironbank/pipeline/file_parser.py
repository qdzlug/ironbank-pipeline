import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .utils import logger
from .utils.exceptions import RepoTypeNotSupported
from .utils.package_parser import (
    ApkPackage,
    DebianPackage,
    GoPackage,
    NpmPackage,
    NullPackage,
    PypiPackage,
    RpmPackage,
    RubyGemPackage,
)
from .utils.types import FileParser, Package

log = logger.setup(name="package_parser")


class AccessLogFileParser(FileParser):
    """Parses access log files to extract and classify packages."""

    @classmethod
    def parse(cls, access_log: list[str] | Path) -> list[Package]:  # W0237
        """Parses the log file and returns a list of packages.

        Parameters:
        access_log: Log to parse. Can be list of strings or a Path object.

        Returns:
        List of Package objects found in the access log.

        Raises:
        ValueError: If a URL in the log cannot be parsed.
        RepoTypeNotSupported: If the repository type from a URL is not supported.
        """
        with Path(os.environ["ACCESS_LOG_REPOS"]).open(mode="r", encoding="utf-8") as f:
            repos = json.load(f)
        packages: list[Package] = []
        nexus_host = os.environ["NEXUS_HOST_URL"]
        nexus_re = re.compile(
            rf"({re.escape(nexus_host)})(?P<repo_type>[^/]+)/(?P<url>.*)"
        )

        for line in cls.handle_file_obj(access_log):
            line = line.rstrip("\n")

            if not line.startswith("200") or line.startswith("200 CONNECT"):
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
                raise RepoTypeNotSupported(
                    f"Repository type not supported: {repo_type}"
                )
            # call desired parser function
            match repos[repo_type]:
                case "gosum":
                    package = NullPackage.parse(re_match.group("url"))
                case "go":
                    package = GoPackage.parse((re_match.group("url")))
                case "rpm":
                    package = RpmPackage.parse((re_match.group("url")))
                case "pypi":
                    package = PypiPackage.parse((re_match.group("url")))
                case "npm":
                    package = NpmPackage.parse((re_match.group("url")))
                case "rubygem":
                    package = RubyGemPackage.parse((re_match.group("url")))
                case "apk":
                    package = ApkPackage.parse((re_match.group("url")))
                case "deb":
                    package = DebianPackage.parse((re_match.group("url")))
                case _:
                    raise RepoTypeNotSupported(
                        f"Repository type not supported: {repos[repo_type]}"
                    )
            packages += [package] if package else []

        log.info("Access log successfully parsed")
        return packages


@dataclass
class SbomFileParser(FileParser):
    """A parser for Sbom."""

    @classmethod
    def parse(cls, sbom: dict | Path) -> list[Package]:  # W0237
        packages: list[Package] = []

        for artifact in cls.handle_file_obj(sbom)["artifacts"]:
            packages.append(
                Package(
                    kind=artifact["type"],
                    name=artifact["name"],
                    version=artifact["version"].split(".el")[0],
                )
            )
        log.info("SBOM successfully parsed")
        return packages


@dataclass
class DockerfileParser(FileParser):
    """A parser for Dockerfiles."""

    @classmethod
    def parse(cls, filepath) -> None:  # W0237
        """Parse the given Dockerfile and return a list of invalid FROM
        statements.

        Parameters
        ----------
        filepath : str
            The path to the Dockerfile to parse.

        Returns
        -------
        List[str]
            A list of invalid FROM statements in the Dockerfile.
        """
        with Path(filepath).open("r", encoding="utf-8") as f:
            parsed_dockerfile = f.readlines()
        from_statement_list = cls.remove_non_from_statements(parsed_dockerfile)
        invalid_from = cls.validate_final_from(from_statement_list)
        return invalid_from

    @staticmethod
    def remove_non_from_statements(dockerfile_lines: tuple) -> list:
        """Remove any lines in the Dockerfile that are not FROM statements.

        Parameters
        ----------
        dockerfile_lines : List[str]
            The lines in the Dockerfile.

        Returns
        -------
        List[str]
            The FROM statements in the Dockerfile.
        """
        return [
            line.rstrip().replace('"', "")
            for line in dockerfile_lines
            if re.match(r"^FROM", line)
        ]

    @staticmethod
    def validate_final_from(content: list):
        """Returns whether the final FROM statement in the Dockerfile is valid,
        i.e. FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}"""
        return content[-1].split(" ")[-1] not in (
            "${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}",
            "$BASE_REGISTRY/$BASE_IMAGE:$BASE_TAG",
        )
