import os, sys, re, argparse
from pathlib import Path
from collections import namedtuple
import logging


LOG_LEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
LOG_FORMAT = "| %(levelname)-5s | %(message)s"
logging.basicConfig(level=LOG_LEVEL, stream=sys.stdout, format=LOG_FORMAT)
logger = logging.getLogger()


REPOS = {
    "ubi-8-baseos": "yum",
    "ubi-8-appstream": "yum",
    "ubi-8-codeready-builder": "yum",
    "goproxy": "go",
}

Package = namedtuple("Package", ["type", "package", "version"])
package_tuples = []


def go_parser(url_path: str) -> Package:

    match = re.match(
        "(?P<name>.*?)/(:?@v/(?P<version>.*?)\.(?P<ext>[^.]+)|(?P<latest>@latest))$",
        url_path,
    )

    if match.group("ext") in ["zip", "info"] or match.group("latest"):
        return None
    elif match.group("ext") != "mod":
        raise ValueError
    else:
        return Package("go", match.group("name"), match.group("version"))


def yum_parser(url_path: str) -> Package:
    if url_path.startswith("repodata"):
        return None

    match = re.match(
        "(?:^|.+/)(?P<name>[^/]+)-(?P<version>[^/-]*-\d+)\.[^/]+\.[^./]+.rpm", url_path
    )

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

    try:
        access_log = open(Path(args.path), "r")
        logger.info(f"File successfully read. Parsing...")
        line_count = 0
        for line in access_log.readlines():
            line_count += 1
            try:
                line = line.rstrip("\n")

                # split on spaces and get the url
                url = line.split(" ")[-1]

                # match against the nexus repo parser
                match = nexus_parser.match(url)

                if not match:
                    raise ValueError()

                # get repository from list
                repo = REPOS[match.group("repo_type")]
                # call desired parser function stored in dictionary
                package = PARSERS[repo](match.group("url"))
                if package:
                    package_tuples.append(package)
                    logger.info(
                        f"Parsed Package: {package.package} version={package.version} type={package.type}"
                    )

            except ValueError:
                logger.error(f"Unable to parse line: {line_count}")
                if not args.allow_errors:
                    exit(0)
        logger.info(f"File Successfully Parsed.")
    except ValueError:
        logger.error("Unable to open file.")
