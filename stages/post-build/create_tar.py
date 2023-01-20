#!/usr/bin/env python3

import os
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.container_tools.skopeo import Skopeo


def main():
    src = Image(
        url=os.environ.get("REGISTRY_URL_STAGING"),
        name=os.environ.get("IMAGE_NAME"),
        digest=os.environ.get("IMAGE_PODMAN_SHA"),
        transport="docker://",
    )
    dest = ImageFile(
        file_path="{}/{}.tar".format(os.environ.get("IMAGE_FILE"), ".tar"),
        transport="docker-archive:",
    )

    skopeo = Skopeo(authfile=os.environ.get("DOCKER_AUTH_CONFIG_FILE_STAGING"))
    skopeo.copy(
        src=src,
        dest=dest,
        log_cmd=True,
    )


if __name__ == "__main__":
    main()
