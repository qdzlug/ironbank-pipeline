#!/usr/bin/env python3

import os

from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.image import Image, ImageFile


def main():
    """
    This function is the entry point for a script that copies a docker image from a registry
    and saves it as a tarball file.

    The script requires the following environment variables to be set:
    - 'REGISTRY_PRE_PUBLISH_URL': The URL of the registry where the source image is stored.
    - 'IMAGE_NAME': The name of the image to be copied.
    - 'IMAGE_PODMAN_SHA': The digest of the image (typically a SHA256 hash).
    - 'IMAGE_FILE': The base name of the file where the image will be saved (without the '.tar' extension).

    The function uses the Skopeo tool to copy the image from the source to the destination. 

    The script does not return anything.

    Raises:
    - SkopeoException: If there's an error during the image copy operation.
    - EnvironmentError: If one of the required environment variables is not set.
    """
    src = Image(
        registry=os.environ["REGISTRY_PRE_PUBLISH_URL"],
        name=os.environ["IMAGE_NAME"],
        digest=os.environ["IMAGE_PODMAN_SHA"],
        transport="docker://",
    )
    dest = ImageFile(
        file_path=f"{os.environ['IMAGE_FILE']}.tar",
        transport="docker-archive:",
    )
    skopeo = Skopeo()
    skopeo.copy(
        src=src,
        src_authfile=os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"],
        dest=dest,
        log_cmd=True,
    )


if __name__ == "__main__":
    main()
