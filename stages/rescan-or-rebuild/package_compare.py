#!/usr/bin/env python3

import sys
import argparse
from pathlib import Path
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.types import Package
from ironbank.pipeline.file_parser import AccessLogFileParser, SbomFileParser
from ironbank.pipeline.container_tools.skopeo import Skopeo

log = logger.setup(
    name="sbom_access_log_parser", format="| %(levelname)-5s | %(message)s"
)


def parse_packages(sbom_path: Path, access_log_path: Path) -> set:
    try:
        pkgs = SbomFileParser.parse(sbom_path)
        pkgs += AccessLogFileParser.parse(access_log_path)
    except OSError as e:
        log.error("Unable to open file")
        log.error(e)
        sys.exit(1)
    except ValueError as e:
        log.error("Unable to parse file")
        log.error(e)
        # TODO:
        # if not args.allow_errors:
        #     sys.exit(1)
    except Exception:
        log.exception("Exception: Unknown exception")
        # TODO:
        # if not args.allow_errors:
        #     sys.exit(1)
    return set(pkgs)
    
def download_artifacts() -> str:
    return Path.cwd() / "cody-test"
    # TODO: Make tmp directory

    # TODO: Download old artifacts to tmp directory

    # return path to tmp directory


def compare(new_pkgs, old_pkgs):
    # Check for package differences
    if new_pkgs.symmetric_difference(old_pkgs):
        log.info("SBOM difference(s) detected!")
        # scan new image
    else:
        log.info("No difference detected!")
        # rescan old image

def main(args) -> None:
    try:
        img = 'redhat/ubi/ubi8'
        tag = 'latest'

        # dsop_project = DsopProject()
        # manifest = HardeningManifest(dsop_project.hardening_manifest_path)
        # skopeo_inspect_json = Skopeo().inspect(manifest.image_name, manifest.image_tag)

        skopeo_inspect_json = Skopeo().inspect(img, tag)

        log.info(skopeo_inspect_json['Digest'])

        # Image may not exist in the registry



        # TODO: Gather information that we need from current & previous image
        #       (Name/tag, Git commit SHA, Parent digest)

        # TODO: Determine if we need to diff SBOMs based on information gathered

       
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
