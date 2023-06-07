#!/usr/bin/env python3

import os

from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.image import Image, ImageFile


def main():
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
