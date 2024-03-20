import json
import os
import sys
from pathlib import Path
from typing import Optional

from pipeline.container_tools.cosign import Cosign
from pipeline.container_tools.skopeo import Skopeo
from pipeline.hardening_manifest import HardeningManifest
from pipeline.image import Image
from pipeline.project import DsopProject
from pipeline.utils.exceptions import GenericSubprocessError
from common.utils import logger

log = logger.setup("image_verify")


def inspect_old_image(
    manifest: HardeningManifest, docker_config_dir: Path
) -> Optional[dict]:
    """Inspects the old image using skopeo tool.

    :param manifest: The HardeningManifest object containing image
        details.
    :param docker_config_dir: Path object indicating the directory of
        the Docker config file.
    :return: A dictionary containing the inspection data of the old
        image or None if GenericSubprocessError is raised.
    """
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


def verify_image_properties(img_json: dict, manifest: HardeningManifest, platform: str) -> bool:
    """Verifies the properties of the image such as Git commit SHA and parent
    digest.

    :param img_json: A dictionary containing the inspection data of the
        image.
    :param manifest: The HardeningManifest object containing image
        details.
    :return: True if both the old image git commit SHA and the parent
        digest remain the same, False otherwise.
    """
    old_image_sha = img_json["Labels"]["org.opencontainers.image.revision"].lower()
    new_image_sha = os.environ["CI_COMMIT_SHA"].lower()

    old_parent = img_json["Labels"]["mil.dso.ironbank.image.parent"]

    if manifest.base_image_name:
        json_file_path = (
            Path(os.environ["ARTIFACT_STORAGE"]) / "lint" / platform / "base_image.json"
        )
        with json_file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
            base_sha = data["BASE_SHA"]

        new_parent = f"{os.environ['BASE_REGISTRY']}/{manifest.base_image_name}:{manifest.base_image_tag}@{base_sha}"
    else:
        new_parent = ""

    # Check if the old image git commit sha differs
    if old_image_sha == new_image_sha:
        # Check if the parent digest changed
        if old_parent == new_parent:
            return True
        log.info("Parent digest difference detected")
        log.info(f"Old parent digest: {old_parent}")
        log.info(f"New parent digest: {new_parent}")
    else:
        log.info("Git commit SHA difference detected")
        log.info(f"Old image SHA: {old_image_sha}")
        log.info(f"New image SHA: {new_image_sha}")

    return False


def diff_needed(docker_config_dir: Path, build: dict, platform: str) -> Optional[dict]:
    """Checks if a diff is needed by inspecting the old image and verifying its
    properties.

    The function also verifies the image signature with Cosign if the
    image repository is not in staging environment.

    :param docker_config_dir: Path object indicating the directory of
        the Docker config file.
    :param build: build.json per platform
    :return: A dictionary containing the old image's tag, commit SHA,
        digest, and build date if no changes are found, None otherwise.
    :raises KeyError: If a key is missing in the old image's JSON
        representation.
    """
    try:
        dsop_project = DsopProject()
        manifest = HardeningManifest(dsop_project.hardening_manifest_path)

        old_image = Image(
            registry=os.environ["REGISTRY_PUBLISH_URL"],
            name=manifest.image_name,
            tag=f"{manifest.image_tag}-{build['PLATFORM']}",
            transport="docker://",
        )

        log.info("Inspecting old image")
        old_img_json = inspect_old_image(manifest, docker_config_dir)

        cosign_verify = True
        # Skip cosign verify in staging as it will fail
        # TODO: Investigate getting cosign verify working in staging environment
        prod_envs = ["repo1.dso.mil", "repo1.il5.dso.mil"]
        if any(x in os.environ["CI_SERVER_URL"] for x in prod_envs):
            log.info("Verify old image signature")
            cosign = Cosign()
            cosign_verify = cosign.verify(
                image=old_image.from_image(transport=""),
                docker_config_dir=docker_config_dir,
                use_key=True,
                log_cmd=True,
            )

        log.info("Verifying image properties")
        # Return old image information if all are true:
        #  - manifest exists for tag (i.e. this pipeline is not running to create a new tag)
        #  - git commit SHAs match
        #  - parent digests match
        if (
            old_img_json
            and verify_image_properties(old_img_json, manifest, platform)
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
    except KeyError as e:
        log.info("Digest or label missing for old image")
        log.info(e)
        sys.exit(1)
    return None
