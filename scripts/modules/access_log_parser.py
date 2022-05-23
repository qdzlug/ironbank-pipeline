import os
import sys
import re
import argparse
from pathlib import Path
from collections import namedtuple

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from utils import logger  # noqa: E402

log = logger.setup(name="access_log_parser", format="| %(levelname)-5s | %(message)s")


REPOS = {
    "goproxy": "go",
    "gosum": "gosum",
    "ubi-7": "yum",
    "ubi-7-extras": "yum",
    "ubi-7-optional": "yum",
    "ubi-7-rhah": "yum",
    "ubi-7-rhscl": "yum",
    "ubi-8-appstream": "yum",
    "ubi-8-baseos": "yum",
    "ubi-8-codeready-builder": "yum",
    "ubigroup-7Server": "yum",
    "ubigroup-8": "yum",
}

Package = namedtuple("Package", ["type", "package", "version"])
package_tuples = []


def go_parser(url_path: str) -> Package:

    match = re.match(
        r"(?P<name>.*?)/(:?@v/(?P<version>.*?)\.(?P<ext>[^.]+)|(?P<latest>@latest))$",
        url_path,
    )

    if not match:
        raise ValueError(f"Could not parse go URL: {url_path}")

    if match.group("ext") in ["zip", "info"] or match.group("latest"):
        return None
    elif match.group("ext") != "mod":
        raise ValueError(f"Unexpected go mod extension: {url_path}")
    else:
        return Package("go", match.group("name"), match.group("version"))


def yum_parser(url_path: str) -> Package:

    if url_path.startswith("repodata"):
        return None

    match = re.match(
        r"(?:^|.+/)(?P<name>[^/]+)-(?P<version>[^/-]*-\d+)\.[^/]+\.[^./]+.rpm", url_path
    )

    if not match:
        raise ValueError(f"Could not parse yum URL: {url_path}")

    return (
        Package("yum", match.group("name"), match.group("version")) if match else None
    )


def null_parser(url: str) -> None:
    return None


PARSERS = {
    "gosum": null_parser,
    "go": go_parser,
    "yum": yum_parser,
}


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

    nexus_host = "http://nexus-repository-manager.nexus-repository-manager.svc.cluster.local:8081/repository/"
    nexus_parser = re.compile(
        f"({re.escape(nexus_host)})(?P<repo_type>[^/]+)/(?P<url>.*)"
    )

    log.info("Access log parser started")
    try:
        access_log = Path(args.path).open("r")
        log.info("File successfully read")
        line_count = 0
    except OSError:
        log.error(f"Unable to open file: {args.path}")
        sys.exit(1)

    with access_log:
        for line in access_log.readlines():
            line_count += 1
            try:
                line = line.rstrip("\n")

                if not line.startswith("200"):
                    continue

                # split on spaces and get the url
                url = line.split(" ")[-1]

                # match against the nexus repo parser
                match = nexus_parser.match(url)

                if not match:
                    raise ValueError(f"Could not find parser for URL: {url}")

                repo_type = match.group("repo_type")
                # get repository from list
                if repo_type not in REPOS:
                    raise ValueError(f"Repository type not supported: {repo_type}")

                repo = REPOS[repo_type]
                # call desired parser function stored in dictionary
                package = PARSERS[repo](match.group("url"))
                if package:
                    package_tuples.append(package)
                    log.info(
                        f"Parsed package: {package.package} version={package.version} type={package.type}"
                    )

            except ValueError as e:
                log.error(f"Unable to parse line: {line_count}")
                log.error(e)
                if not args.allow_errors:
                    sys.exit(1)
            except Exception:
                log.exception("Exception: Unknown exception")
                # TODO: Consider adding custom exception handler to reduce repetition
                if not args.allow_errors:
                    sys.exit(1)
    log.info("File successfully parsed")
