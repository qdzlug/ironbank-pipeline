import sys
import os
import re
import argparse
import json
import utils.parser
from pathlib import Path
from utils import logger
from utils.sbom import Package
from dataclasses import dataclass

log = logger.setup(name="access_log_parser", format="| %(levelname)-5s | %(message)s")


@dataclass
class AccessLogParser(utils.parser.Parser):
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
                        package = utils.parser.NullPackageParser(
                            url=match.group("url")
                        ).parse()
                    case "go":
                        package = utils.parser.GoPackageParser(
                            url=match.group("url")
                        ).parse()
                    case "yum":
                        package = utils.parser.YumPackageParser(
                            url=match.group("url")
                        ).parse()

                if package:
                    packages.append(package)
                    log.info(
                        f"Parsed package: {package.name} version={package.version} type={package.type}"
                    )

        log.info(f"access_log successfully parsed")
        return packages


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script used to parse access_log files"
    )
    parser.add_argument(
        "--allow-errors",
        action="store_true",
        help="allow parsing to continue upon encountering an error",
    )
    parser.add_argument(
        "path",
        type=str,
        help="path to access_log file",
    )
    args = parser.parse_args()

    access_log_parser = AccessLogParser(
        file=args.path, repos=json.load(open(os.environ.get("ACCESS_LOG_REPOS"), "r"))
    )
    try:
        access_log_parser.parse_access_log()
    except OSError:
        log.error(f"Unable to open file: {args.path}")
        sys.exit(1)
    except ValueError as e:
        log.error(f"Unable to parse access_log: {args.path}")
        log.error(e)
        if not args.allow_errors:
            sys.exit(1)
    except Exception:
        log.exception("Exception: Unknown exception")
        # TODO: Consider adding custom exception handler to reduce repetition
        if not args.allow_errors:
            sys.exit(1)
