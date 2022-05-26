import sys
import re
import argparse
from pathlib import Path
from collections import namedtuple
from typing import Optional
from utils import logger
import json

log = logger.setup(name="sbom_parser", format="| %(levelname)-5s | %(message)s")

Package = namedtuple("Package", ["type", "package", "version"])
package_tuples = []


def parse_artifact(artifact: object) -> Optional[Package]:

    return (
        Package(artifact['type'], artifact['name'], artifact['version'])
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script used to parse sbom files"
    )
    parser.add_argument(
        "--allow-errors",
        action="store_true",
        help="allow parsing to continue upon encountering an error",
    )
    parser.add_argument(
        "path",
        type=str,
        help="path to sbom file",
    )
    args = parser.parse_args()

    log.info("SBOM parser started")
    try:
        sbom = Path(args.path).open("r")
        log.info("File successfully read")
    except OSError:
        log.error(f"Unable to open file: {args.path}")
        sys.exit(1)

    with sbom:
        try:
            data = json.load(sbom)
            for artifact in data['artifacts']:

                package = parse_artifact(artifact)

                if package:
                    package_tuples.append(package)
                    log.info(
                        f"Parsed package: {package.package} version={package.version} type={package.type}"
                    )
        except ValueError as e:
                log.error(f"Unable to parse sbom")
                log.error(e)
                if not args.allow_errors:
                    sys.exit(1)
        except Exception:
            log.exception("Exception: Unknown exception")
            # TODO: Consider adding custom exception handler to reduce repetition
            if not args.allow_errors:
                sys.exit(1)

    log.info("File successfully parsed")
