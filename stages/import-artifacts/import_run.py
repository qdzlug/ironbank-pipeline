#!/usr/bin/env python3

import os
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.container_tools.skopeo import Skopeo

def main():

    staging_auth = os.environ.get("DOCKER_AUTH_CONFIG_FILE_STAGING")

    src = Image(
        url=os.environ.get("REGISTRY_URL_STAGING"),
        digest=os.environ.get("IMAGE_PODMAN_SHA"),
        name=os.environ.get("IMAGE_NAME"),
        transport="docker://",
    )
    dest = ImageFile(file_path="{}/{}.tar".format(os.environ.get("IMAGE_FILE"),".tar"), transport="docker-archive:")

    skopeo = Skopeo(authfile=staging_auth)
    skopeo.copy(
        src=src,
        dest=dest,
        src_authfile=staging_auth,
        log_cmd=True,
    )


if __name__ == "__main__":
    main()
