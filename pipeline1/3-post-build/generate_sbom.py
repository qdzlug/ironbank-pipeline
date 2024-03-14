#!/usr/bin/env python3

import logging
import os
import subprocess
import sys
from functools import partial
from multiprocessing.pool import ThreadPool as Pool
from pathlib import Path

# pylint: disable=C0413
sys.path.append(Path(__file__).absolute().parents[2].as_posix())


def generate_sbom(
    image, platform, artifacts_path, output_format, file_type, filename=None
):
    """
    Grab the SBOM from Anchore

    """
    if not filename:
        filename = output_format
    else:
        filename = f"{filename}-{output_format}"

    cmd = [
        "syft",
        image,
        "--platform",
        f"linux/{platform}",
        "--scope",
        "all-layers",
        "-o",
        f"{output_format}",
    ]

    sbom_dir = Path(artifacts_path)
    sbom_dir.mkdir(parents=True, exist_ok=True)
    with (sbom_dir / f"sbom-{filename}.{file_type}").open("wb") as f:
        try:
            logging.info(" ".join(cmd))
            subprocess.run(
                cmd,
                check=True,
                encoding="utf-8",
                stderr=sys.stderr,
                stdout=f,
            )
        except subprocess.SubprocessError:
            logging.error("Could not generate sbom of image")
            sys.exit(1)


def generate_sbom_parallel(image, platform, artifacts_path, fmt) -> None:
    """Helper function which selects the appropriate args when calling
    generate_sbom."""
    generate_sbom(image, platform, artifacts_path, fmt[0], fmt[1], fmt[2])


def main() -> None:
    """Main function that initializes an Anchore scanner and generates Software
    Bill of Materials (SBOM) in multiple formats for a specified image.

    The function retrieves configuration parameters from environment variables including the Anchore scanner
    details and the full tag of the image for scanning. It also gets the path for storing SBOM files which
    defaults to "/tmp/sbom_dir" if not provided.

    The SBOMs are generated in the following formats:
    - cyclonedx-json
    - spdx-tag-value
    - spdx-json
    - json (using Syft tool)

    All SBOM files are saved in the specified path or the default path if not provided.

    :raises KeyError: If required environment variables are not set.
    """

    # generate sbom for platforms (if digest artifact exists)
    potential_platforms = [
        "amd64",
        "arm64",
    ]

    platforms = [
        platform
        for platform in potential_platforms
        if os.path.isfile(f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/digest')
    ]

    sbom_formats = [
        ("cyclonedx-json", "json", None),
        ("spdx-tag-value", "txt", None),
        ("spdx-json", "json", None),
        ("json", "json", "syft"),
    ]

    for platform in platforms:
        print(f"generating for {platform}..")
        with Pool() as pool:
            # create intermediate function to hold arguments which are always the same (image, platform, and artifact path)
            partial_generate_sbom = partial(
                generate_sbom_parallel,
                os.environ["IMAGE_FULLTAG"],
                platform,
                f'{os.environ["ARTIFACT_DIR"]}/{platform}',
            )
            # map each format tuple to partial_generate_sbom and add it to the pool
            pool.map(partial_generate_sbom, sbom_formats)


if __name__ == "__main__":
    main()
