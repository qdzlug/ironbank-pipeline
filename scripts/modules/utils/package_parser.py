import re
from utils import logger
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

log = logger.setup(name="package_parser", format="| %(levelname)-5s | %(message)s")


@dataclass
class Parser:
    file: Path = None

    def parse(self):
        pass


@dataclass
class Package:
    type: str = None
    name: str = None
    version: str = None
    url: str = None


@dataclass
class YumPackageParser(Package, Parser):
    def parse(self) -> Optional[Package]:
        if self.url.startswith("repodata"):
            return None

        match = re.match(
            r"(?:^|.+/)(?P<name>[^/]+)-(?P<version>[^/-]*-\d+)\.[^/]+\.[^./]+.rpm",
            self.url,
        )

        if not match:
            raise ValueError(f"Could not parse yum URL: {self.url}")

        return (
            Package("rpm", match.group("name"), match.group("version"), self.url)
            if match
            else None
        )


@dataclass
class GoPackageParser(Package, Parser):
    def parse(self) -> Optional[Package]:

        match = re.match(
            r"(?P<name>.*?)/(:?@v/(?P<version>.*?)\.(?P<ext>[^.]+)|(?P<latest>@latest)|(?P<list>list))$",
            self.url,
        )

        if not match:
            raise ValueError(f"Could not parse go URL: {self.url}")
        elif (
            match.group("ext") in ["zip", "info"]
            or match.group("latest")
            or match.group("list")
        ):
            return None
        elif match.group("ext") and match.group("ext") != "mod":
            raise ValueError(f"Unexpected go mod extension: {self.url}")
        else:
            return Package("go", match.group("name"), match.group("version"), self.url)


@dataclass
class NullPackageParser(Package, Parser):
    def parse(self) -> None:
        return None


# TODO AccessLogParser is relly a "FileParser", we should consider refactoring, along iwth what's currently in sbom_parser.py
@dataclass
class AccessLogParser(Parser):
    repos: dict = None

    def parse_access_log(self) -> list[Package]:
        packages = [Package]
        # TODO make this an environment variable
        nexus_host = "http://nexus-repository-manager.nexus-repository-manager.svc.cluster.local:8081/repository/"
        nexus_re = re.compile(
            f"({re.escape(nexus_host)})(?P<repo_type>[^/]+)/(?P<url>.*)"
        )

        log.info("Access log parser started")
        access_log = Path(self.file).open("r")
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
                match = nexus_re.match(url)

                if not match:
                    raise ValueError(f"Could not parse URL: {url}")

                repo_type = match.group("repo_type")

                # get repository from list
                if repo_type not in self.repos:
                    raise ValueError(f"Repository type not supported: {repo_type}")

                # call desired parser function
                match self.repos[repo_type]:
                    case "gosum":
                        package = NullPackageParser(url=match.group("url")).parse()
                    case "go":
                        package = GoPackageParser(url=match.group("url")).parse()
                    case "yum":
                        package = YumPackageParser(url=match.group("url")).parse()

                if package:
                    packages.append(package)
                    log.info(
                        f"Parsed package: {package.name} version={package.version} type={package.type}"
                    )

        log.info("access_log successfully parsed")
        return packages
