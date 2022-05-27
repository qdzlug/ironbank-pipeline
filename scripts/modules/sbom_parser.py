import sys
import argparse
from pathlib import Path
from utils import logger
from utils.sbom import Package
import json

log = logger.setup(name="sbom_parser", format="| %(levelname)-5s | %(message)s")

def parse_sbom(path: Path, allow_errors: bool) -> list[Package]:

    package_tuples = []
    log.info("SBOM parser started")
    try:
        sbom = Path(path).open("r")
        log.info("File successfully read")
    except OSError:
        log.error(f"Unable to open file: {path}")
        sys.exit(1)

    with sbom:
        try:
            data = json.load(sbom)
            for artifact in data['artifacts']:

                package = Package(artifact['type'], artifact['name'], artifact['version'].split('.el')[0])

                if package:
                    package_tuples.append(package)
                    log.info(
                        f"Parsed package: {package.package} version={package.version} type={package.type}"
                    )
        except ValueError as e:
                log.error(f"Unable to parse sbom")
                log.error(e)
                if not allow_errors:
                    sys.exit(1)
        except Exception:
            log.exception("Exception: Unknown exception")
            # TODO: Consider adding custom exception handler to reduce repetition
            if not allow_errors:
                sys.exit(1)

    log.info("File successfully parsed")
    return package_tuples


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

    parse_sbom(args.path, args.allow_errors)    
