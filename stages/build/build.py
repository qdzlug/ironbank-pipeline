import os
import sys
import argparse
import subprocess
from pathlib import Path

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.utils import logger
log = logger.setup("build")

# resource_type set to file by default so image is explicitly set
# resource_type is not used unless value = image, but it is set to file for clarity of purpose
# TODO: consider passing a true "type" for resource_type (i.e. resource_type = Image or resource_type = Path)
def load_resources(resource_dir: str, resource_type: str = 'file', skopeo: Skopeo = None):
    for resource_file in os.listdir(resource_dir):
        resource_file_obj = Path(resource_dir, resource_file)
        if resource_file_obj.isfile() and not resource_file_obj.is_symlink():
            if resource_type == "image" and skopeo:
                manifest_json = subprocess.run(["tar", "-xf", resource_file_obj.as_posix(), "-O", "manifest.json"])
                image_name = manifest_json[0]['RepoTags']
                skopeo.copy(ImageFile(file_path=resource_file_obj, transport="docker-archive:"), Image(url=image_name, transport="containers-storage:"))
            else:
                os.rename(resource_file_obj, Path(resource_file))
        else:
            log.error("Resource type is invalid")
            sys.exit(1)

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
    load_resources(resource_dir=image_dir, resource_type="image", skopeo=skopeo)
    load_resources(resource_dir=resource_dir)




    log.info("Load any images used in Dockerfile build")


if __name__ == "__main__":
    main()
