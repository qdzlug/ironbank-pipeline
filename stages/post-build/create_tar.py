import os
import base64
from ironbank.pipeline.utils import logger
from ironbank.pipeline.container_tools.skopeo import Skopeo

log = logger.setup(name="create_container_image_tar")
log.info("Creating json Auth file staging_auth.json")
with open("staging_auth.json", "w") as json_auth:
    json_auth.write(
        f"{base64.b64encode(bytes(os.environ['DOCKER_AUTH_CONFIG_STAGING']))}"
    )
log.info(
    f"Creating tarball from docker://{os.environ['REGISTRY_URL_STAGING']}/{os.environ['IMAGE_NAME']}@{os.environ['IMAGE_PODMAN_SHA']} to: docker-archive:{os.environ['IMAGE_FILE']}.tar"
)
try:
    Skopeo.copy(
        src=f"docker://{os.environ['REGISTRY_URL_STAGING']}/{os.environ['IMAGE_NAME']}@{os.environ['IMAGE_PODMAN_SHA']}",
        src_authfile="./staging_auth.json",
        dest=f"docker-archive:{os.environ['IMAGE_FILE']}.tar",
    )
except Exception as tar_create_fail:
    log.exception(f"Failed to create container image export:\n{tar_create_fail}")
