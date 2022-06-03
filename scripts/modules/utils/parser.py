import utils.package_parser
import logger
import re
from pathlib import Path
from dataclasses import dataclass
from utils.sbom import Package

log = logger.setup(name="parser", format="| %(levelname)-5s | %(message)s")

@dataclass
class Parser:
    file: Path = None

    def parse(self):
        pass

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
                        package = utils.package_parser.NullPackageParser(
                            url=match.group("url")
                        ).parse()
                    case "go":
                        package = utils.package_parser.GoPackageParser(
                            url=match.group("url")
                        ).parse()
                    case "yum":
                        package = utils.package_parser.YumPackageParser(
                            url=match.group("url")
                        ).parse()

                if package:
                    packages.append(package)
                    log.info(
                        f"Parsed package: {package.name} version={package.version} type={package.type}"
                    )

        log.info("access_log successfully parsed")
        return packages

