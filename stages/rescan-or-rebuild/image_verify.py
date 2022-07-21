import json
import os
import pathlib
import subprocess
from typing import Optional
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.utils import logger
from ironbank.pipeline.container_tools.skopeo import Skopeo

log = logger.setup("image_verify")


def inspect_old_image(manifest: HardeningManifest) -> Optional[dict]:
    try:
        return Skopeo().inspect(manifest.image_name, manifest.image_tag)

    except subprocess.CalledProcessError:
        log.info("Failed to inspect old image.")
        return None


def commit_sha_equal(img_json: dict) -> bool:
    # Check if the git sha in the old labels is different
    #   if different, no diff needed: new commit

    if "org.opencontainers.image.revision" not in img_json["Labels"]:
        log.info("Image revision label does not exist.")
        return False

    if (
        img_json["Labels"]["org.opencontainers.image.revision"].lower()
        == os.environ["CI_COMMIT_SHA"].lower()
    ):
        return True
    else:
        log.info("Git commit SHA difference detected.")
        return False


def parent_digest_equal(img_json: dict, manifest: HardeningManifest) -> bool:
    # check if the parent digest changed (will need to inspect the parent too to get it's new digest)
    #   if different, no diff needed: updated parent

    if "mil.dso.ironbank.image.parent" not in img_json["Labels"]:
        log.info("Parent image label does not exist.")
        return False

    with pathlib.Path(os.environ["ARTIFACT_DIR"], "base_image.json").open("w") as f:
        base_sha = json.load(f)["BASE_SHA"]

    new_parent = (
        f"{os.environ['BASE_REGISTRY']}/{manifest.base_image_name}:{manifest.base_image_tag}@{base_sha}"
        if manifest.base_image_name
        else ""
    )

    if new_parent == img_json["Labels"]["mil.dso.ironbank.image.parent"]:
        return True
    else:
        log.info("Parent digest difference detected.")
        return False


def diff_needed() -> Optional[str]:

    dsop_project = DsopProject()
    manifest = HardeningManifest(dsop_project.hardening_manifest_path)

    old_img_json = inspect_old_image(manifest)

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
        f"{os.environ['BASE_REGISTRY']}/{manifest.image_name}@{old_img_json['Digest']}"
    )
