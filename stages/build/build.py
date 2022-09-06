import os
from pathlib import Path

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.utils import logger

log = logger.setup("build")


def load_images(image_path: Path):
    for file_name in os.listdir(image_path):
        pass


def main():
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    staging_image = Image(
        registry=os.environ["REGISTRY_URL_STAGING"],
        name=os.environ["IMAGE_NAME"],
        tag=f"ibci-{os.environ['CI_PIPELINE_ID']}",
    )
    os.makedirs(Path(os.environ["ARTIFACT_DIR"]))
    base_registry = os.environ["BASE_REGISTRY"]
    pull_creds = None

    log.info("Determine source registry based on branch")
    if os.environ.get("STAGING_BASE_IMAGE"):
        base_registry = f"{base_registry}-staging"
        pull_creds = os.environ["DOCKER_AUTH_CONFIG_STAGING"]


if __name__ == "__main__":
    main()
