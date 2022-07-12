#!/usr/bin/env python3

from ironbank.pipeline.stargate import Stargate
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest


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
