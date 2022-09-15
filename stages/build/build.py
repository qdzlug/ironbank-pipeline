import os
import argparse
import subprocess
from pathlib import Path

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.utils import logger
log = logger.setup("build")


def load_images(image_path: Path):
    for file_name in os.listdir(image_path):
        pass


def main():
    parser = argparse.ArgumentParser(description="Script used for building ironbank images")
    parser.add_argument(
        "--imported-artifacts-path",
        "--imports-path",
        default=Path(f"{os.environ['ARTIFACT_STORAGE']}", 'import-artifacts'),
        type=str,
        help="path to imported binaries and images"
    )

    args = parser.parse_args()

    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    staging_image = Image(
        registry=os.environ["REGISTRY_URL_STAGING"],
        name=os.environ["IMAGE_NAME"],
        tag=f"ibci-{os.environ['CI_PIPELINE_ID']}",
    )
    skopeo = Skopeo()
    base_registry = os.environ["BASE_REGISTRY"]
    pull_creds = None
    image_dir = Path(f"{args.imports_path}/images")
    resource_dir = Path(f"{args.imports_path}/external_resources")

    os.makedirs(Path(os.environ["ARTIFACT_DIR"]))

    log.info("Determine source registry based on branch")
    if os.environ.get("STAGING_BASE_IMAGE"):
        base_registry += "-staging"
        pull_creds = os.environ["DOCKER_AUTH_CONFIG_STAGING"]

    # gather files and subpaths
    for image_file in os.listdir(image_dir):
        image_file_obj = Path(image_file)
        if image_file_obj.isfile() and not image_file_obj.is_symlink():
            manifest_json = subprocess.run(["tar", "-xf", image_file_obj.as_posix(), "-O", "manifest.json"])
            image_name = manifest_json[0]['RepoTags']
            skopeo.copy(ImageFile(file_path=image_file_obj, transport="docker-archive:"), Image(url=image_name, transport="containers-storage:"))

    log.info("Load any images used in Dockerfile build")


if __name__ == "__main__":
    main()
