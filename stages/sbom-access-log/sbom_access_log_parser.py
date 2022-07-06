import os
import sys
import argparse

sys.path.append(
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "modules")
)

from utils import logger  # noqa: E402
from utils.types import Package  # noqa: E402
from file_parser import AccessLogFileParser, SbomFileParser  # noqa: E402

log = logger.setup(
    name="sbom_access_log_parser", format="| %(levelname)-5s | %(message)s"
)


def main(args) -> None:
    try:
        # TODO: Gather information that we need from current & previous image
        #       (Name/tag, Git commit SHA, Parent digest)

        # TODO: Determine if we need to diff SBOMs based on information gathered

        # Parse new sbom & access log
        new_pkgs = SbomFileParser.parse(args.sbom_file)
        new_pkgs += AccessLogFileParser.parse(args.access_log_file)

        # Remove duplicates
        new_pkgs = list(set(new_pkgs))

        # TODO: Make tmp directory

        # TODO: Download old artifacts to tmp directory

        # TODO: Parse old sbom & access log
        # old_pkgs = SbomFileParser.parse()
        # old_pkgs += AccessLogFileParser.parse()

        # TODO: Temporary spoof data - remove when above is implemented
        old_pkgs = [
            Package(kind="tKind1", name="tName1", version="tVersion1", url="tUrl1"),
        ]

        # Remove duplicates
        old_pkgs = list(set(old_pkgs))

        # Check for package differences
        if set(new_pkgs).symmetric_difference(set(old_pkgs)):
            log.info("SBOM difference(s) detected!")
            # scan new image
        else:
            log.info("No difference detected!")
            # rescan old image

    except OSError as e:
        log.error("Unable to open file")
        log.error(e)
        sys.exit(1)
    except ValueError as e:
        log.error("Unable to parse file")
        log.error(e)
        if not args.allow_errors:
            sys.exit(1)
    except Exception:
        log.exception("Exception: Unknown exception")
        # TODO: Consider adding custom exception handler to reduce repetition
        if not args.allow_errors:
            sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script used to parse access_log and sbom files"
    )
    parser.add_argument(
        "--allow-errors",
        action="store_true",
        help="allow parsing to continue upon encountering an error",
    )
    parser.add_argument(
        "sbom_file",
        type=str,
        help="path to sbom file",
    )
    parser.add_argument(
        "access_log_file",
        type=str,
        help="path to access_log file",
    )
    args = parser.parse_args()
    main(args)
