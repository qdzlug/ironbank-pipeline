import sys
import argparse
import json
from pathlib import Path
from utils import logger
from utils.sbom import Package
from utils.parser import Parser
from dataclasses import dataclass

log = logger.setup(name="sbom_parser", format="| %(levelname)-5s | %(message)s")


@dataclass
class SbomParser(Parser):
    def parse_sbom(self) -> list[Package]:

        packages = [Package]
        log.info("SBOM parser started")
        sbom = Path(self.file).open("r")
        log.info("File successfully read")

        with sbom:
            data = json.load(sbom)
            for artifact in data["artifacts"]:

                package = Package(
                    artifact["type"],
                    artifact["name"],
                    artifact["version"].split(".el")[0],
                )

                if package:
                    packages.append(package)
                    log.info(
                        f"Parsed package: {package.name} version={package.version} type={package.type}"
                    )

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
        "path",
        type=str,
        help="path to sbom file",
    )
    args = parser.parse_args()
    sbom_parser = SbomParser(args.path)

    try:
        sbom_parser.parse_sbom()
    except OSError:
        log.error(f"Unable to open file: {sbom_parser.path}")
        sys.exit(1)
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
