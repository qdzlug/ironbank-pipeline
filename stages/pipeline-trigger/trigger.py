#!/usr/bin/env python3

import os
import sys
import tempfile
from base64 import b64decode
from pathlib import Path

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.utils import logger
from ironbank.pipeline.image import Image
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.utils.exceptions import GenericSubprocessError
from ironbank.pipeline.hardening_manifest import (
    get_source_keys_values,
)

log = logger.setup("pipeline_trigger")

artifact_storage = os.environ["ARTIFACT_STORAGE"]
label_dict = get_source_keys_values(f"{artifact_storage}/lint/labels.env")
os_type = label_dict.get("mil.dso.ironbank.os-type")
if not os_type:
    dsop_project = DsopProject()
    manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config_dir:

        docker_config = Path(docker_config_dir, "config.json")
        if os.environ.get("STAGING_BASE_IMAGE"):
            # Grab staging pull docker auth
            pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_STAGING"]).decode(
                "UTF-8"
            )
            registry = os.environ["REGISTRY_URL_STAGING"]
        else:
            # Grab prod docker auth
            pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_PULL"]).decode("UTF-8")
            registry = os.environ["REGISTRY_URL_PROD"]
        docker_config.write_text(pull_auth, encoding="utf-8")
        try:
            skopeo = Skopeo(docker_config_dir=docker_config_dir)
            base_image = Image(
                registry=registry,
                name=manifest.base_image_name,
                tag=manifest.base_image_tag,
                transport="docker://",
            )
            base_img_inspect = skopeo.inspect(base_image, log_cmd=True)
        except GenericSubprocessError:
            log.error(
                "Failed to inspect IMAGE:TAG provided in hardening_manifest. \
                    Please validate this image exists in the registry1.dso.mil/ironbank project."
            )
            log.error("Failed 'skopeo inspect' of image: %s", base_image)
            sys.exit(1)
        os_type = base_img_inspect["Labels"]["mil.dso.ironbank.os-type"]
log.info("OS_TYPE: %s", os_type)
