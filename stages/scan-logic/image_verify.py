import json
import os
import pathlib
import subprocess
from typing import Optional
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.utils import logger
from ironbank.pipeline.image import Image
from ironbank.pipeline.container_tools.skopeo import Skopeo

log = logger.setup("image_verify")


def inspect_old_image(
    manifest: HardeningManifest, docker_config_dir: str
) -> Optional[dict]:
    try:
        skopeo = Skopeo(docker_config_dir=docker_config_dir)
        old_image = Image(
            registry=os.environ["REGISTRY_URL_PROD"],
            name=manifest.image_name,
            tag=manifest.image_tag,
            transport="docker://",
        )
        return skopeo.inspect(old_image)

    except subprocess.CalledProcessError:
        log.info(
            f"Failed to inspect old image (expected if '{manifest.image_tag}' is new tag): {manifest.image_name}:{manifest.image_tag}"
        )
        return None


# TODO: Combine these two functions and rework their logic to not return as many bool False values.
def commit_sha_equal(img_json: dict) -> bool:
    # Check if the git sha in the old labels is different
    #   if different, no diff needed: new commit

    if "org.opencontainers.image.revision" not in img_json["Labels"]:
        log.info("Image revision label does not exist")
        return False

    old_image_sha = img_json["Labels"]["org.opencontainers.image.revision"].lower()
    new_image_sha = os.environ["CI_COMMIT_SHA"].lower()

    if old_image_sha == new_image_sha:
        return True
    else:
        log.info("Git commit SHA difference detected")
        log.info(f"Old image SHA: {old_image_sha}")
        log.info(f"New image SHA: {new_image_sha}")
        return False


def parent_digest_equal(img_json: dict, manifest: HardeningManifest) -> bool:
    # check if the parent digest changed (will need to inspect the parent too to get it's new digest)
    #   if different, no diff needed: updated parent

    if "mil.dso.ironbank.image.parent" not in img_json["Labels"]:
        log.info("Parent image label does not exist")
        return False

    old_parent = img_json["Labels"]["mil.dso.ironbank.image.parent"]

    if manifest.base_image_name:
        with pathlib.Path(
            os.environ["ARTIFACT_STORAGE"], "lint", "base_image.json"
        ).open() as f:
            base_sha = json.load(f)["BASE_SHA"]

        new_parent = f"{os.environ['BASE_REGISTRY']}/{manifest.base_image_name}:{manifest.base_image_tag}@{base_sha}"
    else:
        new_parent = ""

    if old_parent == new_parent:
        return True
    else:
        log.info("Parent digest difference detected")
        log.info(f"Old parent digest: {old_parent}")
        log.info(f"New parent digest: {new_parent}")
        return False


def diff_needed(docker_config_dir: str) -> Optional[tuple]:
    dsop_project = DsopProject()
    manifest = HardeningManifest(dsop_project.hardening_manifest_path)

    log.info("Inspecting old image")
    old_img_json = inspect_old_image(manifest, docker_config_dir)

    log.info("Verifying image properties")
    if not (
        # If manifest exists (not a new tag), return true
        old_img_json
        # If no diff in git commit SHA, return true
        and commit_sha_equal(old_img_json)
        # If no diff in parent digest, return true
        and parent_digest_equal(old_img_json, manifest)
    ):
        return None

    return (
        old_img_json["Digest"],
        # Label created in build stage - should be available
        old_img_json["Labels"]["org.opencontainers.image.created"],
    )
