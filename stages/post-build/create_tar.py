#!/usr/bin/env python3

import os
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.container_tools.skopeo import Skopeo


def main():
    src = Image(
        url=os.environ["REGISTRY_URL_STAGING"],
        name=os.environ["IMAGE_NAME"],
        digest=os.environ["IMAGE_PODMAN_SHA"],
        transport="docker://",
    )
    dest = ImageFile(
        file_path=f"{os.environ['IMAGE_FILE']}.tar",
        transport="docker-archive:",
    )

    skopeo = Skopeo(authfile=os.environ["DOCKER_AUTH_CONFIG_FILE_STAGING"])
    skopeo.copy(
        src=src,
        dest=dest,
        log_cmd=True,
    )


if __name__ == "__main__":
    main()
