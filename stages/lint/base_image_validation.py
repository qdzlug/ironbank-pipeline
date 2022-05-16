#!/usr/bin/env python3

from base64 import b64decode
from encodings import utf_8
import json
import os
import asyncio
import pathlib
import subprocess
import sys

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from project import DsopProject  # noqa: E402
from utils import logger  # noqa: E402
from hardening_manifest import HardeningManifest  # noqa: E402

log = logger.setup(name="lint.base_image_validation")


def skopeo_inspect_base_image(base_image, base_tag):
    #
    # Use the local hardening manifest to get the first parent. From here *only* the
    # the master branch should be used for the ancestry.
    #

    if os.environ.get("STAGING_BASE_IMAGE"):
        auth_file = "staging_pull_auth.json"
        # Grab prod pull docker auth
        pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_STAGING"]).decode("UTF-8")
        pathlib.Path(auth_file).write_text(pull_auth)
        registry = "ironbank-staging"
    else:
        auth_file = "prod_pull_auth.json"
        # Grab staging docker auth
        pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_PULL"]).decode("UTF-8")
        pathlib.Path(auth_file).write_text(pull_auth)
        registry = "ironbank"

    # get parent cves from VAT
    cmd = [
        "skopeo",
        "inspect",
        "--authfile",
        auth_file,
        f"docker://registry1.dso.mil/{registry}/{base_image}:{base_tag}",
        "--format",
        "'{{ .Digest }}'"
    ]
    log.info(" ".join(cmd))
    # if skopeo inspect fails, because BASE_IMAGE value doesn't match a registry1 container name
    #   fail back to using existing functionality
    try:
        sha_value = subprocess.run(
            args=cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            encoding="utf-8"
        )
        base_image_info = {"BASE_SHA": sha_value.stdout.strip().replace("'", "")}
        with open(f'{os.environ["ARTIFACT_DIR"]}/base_image.json', 'w') as f:
            json.dump(base_image_info, f)
    except subprocess.CalledProcessError as e:
        log.error(
            "Failed to inspect BASE_IMAGE:BASE_TAG provided in hardening_manifest. \
                Please validate this image exists in the registry1.dso.mil/ironbank project."
        )
        log.error(
            f"Failed 'skopeo inspect' of image: \
                registry1.dso.mil/{registry}/{base_image}:{base_tag} "
        )
        log.error(f"Return code: {e.returncode}")
        sys.exit(1)
    except Exception:
        log.exception("Unknown failure when attemping to inspect BASE_IMAGE")
        sys.exit(1)


async def main():
    #
    # Hardening manifest is expected for all of the current repos that are being processed.
    # At the very least the hardening_manifest.yaml should be generated if it has not been
    # merged in yet.
    #
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)

    if hardening_manifest.base_image_name:
        skopeo_inspect_base_image(
            hardening_manifest.base_image_name, hardening_manifest.base_image_tag
        )


if __name__ == "__main__":
    asyncio.run(main())
