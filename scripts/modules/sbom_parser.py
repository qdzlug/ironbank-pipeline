import sys
import argparse
import json
from pathlib import Path
from utils import logger
from utils import Package, FileParser
from dataclasses import dataclass

log = logger.setup(name="sbom_parser", format="| %(levelname)-5s | %(message)s")


@dataclass
class SbomParser(FileParser):
    @classmethod
    def parse(cls, file) -> list[Package]:

        packages: [Package] = []
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script used to parse sbom files")
    parser.add_argument(
        "--allow-errors",
        action="store_true",
        help="allow parsing to continue upon encountering an error",
    )
    parser.add_argument(
        "file",
        type=str,
        help="path to sbom file",
    )
    args = parser.parse_args()

    try:
        SbomParser.parse(Path(args.file).open("r"))
    except OSError:
        log.error(f"Unable to open file: {args.file}")
        sys.exit(1)
    except ValueError as e:
        log.error("Unable to parse sbom")
        log.error(e)
        if not args.allow_errors:
            sys.exit(1)
    except Exception:
        log.exception("Exception: Unknown exception")
        # TODO: Consider adding custom exception handler to reduce repetition
        if not args.allow_errors:
            sys.exit(1)
