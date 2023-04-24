import os
import shutil
import sys
import json
import tempfile
from pathlib import Path
from typing import Optional
from ironbank.pipeline.image import Image
from ironbank.pipeline.utils import logger
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.utils.exceptions import GenericSubprocessError

log = logger.setup("image_verify")


def inspect_old_image(
    manifest: HardeningManifest, docker_config_dir: Path
) -> Optional[dict]:
    try:
        skopeo = Skopeo(docker_config_dir=docker_config_dir)
        old_image = Image(
            registry=os.environ["REGISTRY_PUBLISH_URL"],
            name=manifest.image_name,
            tag=manifest.image_tag,
            transport="docker://",
        )
        return skopeo.inspect(old_image, log_cmd=True)

    except GenericSubprocessError:
        log.info(
            f"Failed to inspect old image (expected if '{manifest.image_tag}' is new tag): {manifest.image_name}:{manifest.image_tag}"
        )
        return None


def verify_image_properties(img_json: dict, manifest: HardeningManifest) -> bool:
    old_image_sha = img_json["Labels"]["org.opencontainers.image.revision"].lower()
    new_image_sha = os.environ["CI_COMMIT_SHA"].lower()

    old_parent = img_json["Labels"]["mil.dso.ironbank.image.parent"]
    if manifest.base_image_name:
        with Path(
            os.environ["ARTIFACT_STORAGE"], "lint", "base_image.json"
        ).open() as f:
            base_sha = json.load(f)["BASE_SHA"]

        new_parent = f"{os.environ['BASE_REGISTRY']}/{manifest.base_image_name}:{manifest.base_image_tag}@{base_sha}"
    else:
        new_parent = ""

    # Check if the old image git commit sha differs
    if old_image_sha == new_image_sha:
        # Check if the parent digest changed
        if old_parent == new_parent:
            return True
        else:
            log.info("Parent digest difference detected")
            log.info(f"Old parent digest: {old_parent}")
            log.info(f"New parent digest: {new_parent}")
    else:
        log.info("Git commit SHA difference detected")
        log.info(f"Old image SHA: {old_image_sha}")
        log.info(f"New image SHA: {new_image_sha}")

    return False


def diff_needed(docker_config_dir: Path) -> Optional[dict]:
    try:
        dsop_project = DsopProject()
        manifest = HardeningManifest(dsop_project.hardening_manifest_path)

        old_image = Image(
            registry=os.environ["REGISTRY_PUBLISH_URL"],
            name=manifest.image_name,
            tag=manifest.image_tag,
            transport="docker://",
        )

        log.info("Inspecting old image")
        old_img_json = inspect_old_image(manifest, docker_config_dir)

        log.info("Verify old image signature")
        cosign_verify = True
        # Skip cosign verify in staging as it will fail
        if "repo1.dso.mil" in os.environ["CI_SERVER_URL"]:
            cosign_verify = Cosign.verify(
                image=old_image.from_image(transport=""),
                docker_config_dir=docker_config_dir,
                log_cmd=True,
            )

        log.info("Verifying image properties")
        # Return old image information if all are true:
        #  - manifest exists for tag (i.e. this pipeline is not running to create a new tag)
        #  - git commit SHAs match
        #  - parent digests match
        if (
            old_img_json
            and verify_image_properties(old_img_json, manifest)
            and cosign_verify
        ):
            return {
                # Old image information to return
                "tag": manifest.image_tag,
                "commit_sha": old_img_json["Labels"][
                    "org.opencontainers.image.revision"
                ].lower(),
                "digest": old_img_json["Digest"],
                "build_date": old_img_json["Labels"][
                    "org.opencontainers.image.created"
                ],
            }
    except KeyError as ke:
        log.info("Digest or label missing for old image")
        log.info(ke)
        sys.exit(1)
    return None
