import re
import os
import json

import dockerfile
from utils import logger
from pathlib import Path
from dataclasses import dataclass
from utils.types import FileParser, Package
from utils.exceptions import DockerfileParseError
from utils.package_parser import (
    GoPackage,
    YumPackage,
    PypiPackage,
    NpmPackage,
    RubyGemPackage,
    NullPackage,
)

log = logger.setup(name="package_parser", format="| %(levelname)-5s | %(message)s")


class AccessLogFileParser(FileParser):
    @classmethod
    def parse(cls, file: str) -> list[Package]:
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

        with access_log:
            for line in access_log.readlines():
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
                    case "npm":
                        package = NpmPackage.parse((re_match.group("url")))
                    case "rubygem":
                        package = RubyGemPackage.parse((re_match.group("url")))

                if package:
                    packages.append(package)
                    log.info(f"Parsed package: {package}")

        log.info("Access log successfully parsed")
        return packages


@dataclass
class SbomFileParser(FileParser):
    @classmethod
    def parse(cls, file: str) -> list[Package]:

        packages: list[Package] = []
        log.info("SBOM parser started")
        sbom = Path(file).open("r")
        log.info("SBOM successfully read")

        with sbom:
            data = json.load(sbom)
            for artifact in data["artifacts"]:

                package = Package(
                    kind=artifact["type"],
                    name=artifact["name"],
                    version=artifact["version"].split(".el")[0],
                )

                if package:
                    packages.append(package)
                    log.info(f"Parsed package: {package}")

            log.info("SBOM successfully parsed")
        return packages


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
