#!/usr/bin/env python3

import os
import sys

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from stargate import Stargate  # noqa: E402
from project import DsopProject  # noqa: E402
from hardening_manifest import HardeningManifest  # noqa: E402


def main() -> None:
    """
    Create and push Star Gate package
    """
    stargate_object = Stargate()
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    image_title = hardening_manifest.labels["org.opencontainers.image.title"]
    image_description = hardening_manifest.labels[
        "org.opencontainers.image.description"
    ]
    stargate_object.create_image_directory(image_title)
    stargate_object.generate_metadata(
        stargate_object.image_dir,
        image_description,
        stargate_object.archive_directory_name,
    )
    stargate_object.create_archive()
    stargate_object.push_artifacts(
        stargate_object.archive_directory_name,
        stargate_object.s3_bucket,
    )


if __name__ == "__main__":
    main()
