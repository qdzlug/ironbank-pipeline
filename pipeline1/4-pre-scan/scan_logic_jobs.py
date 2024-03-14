#!/usr/bin/env python3

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import image_verify

from pipeline.container_tools.cosign import Cosign
from pipeline.file_parser import AccessLogFileParser, SbomFileParser
from pipeline.image import Image
from pipeline.utils.exceptions import CosignDownloadError
from pipeline.utils.types import Package
from common.utils import logger
import urllib
import requests

log = logger.setup("scan_logic_jobs")


def write_env_vars(
    image_name_tag: str, commit_sha: str, digest: str, build_date: str, platform: str
) -> None:
    """Writes environment variables into a file named 'scan_logic.env'.

    This function takes the image name and tag, commit SHA, image digest,
    and the build date. It then writes these as environment variables
    into a file named 'scan_logic.env' and 'scan_logic.json'.

    Arguments:
    - image_name_tag: The name and tag of the image to scan.
    - commit_sha: The SHA of the commit to scan.
    - digest: The digest of the image to scan.
    - build_date: The date when the build was created.
    """
    log.info(f"Writing {os.environ['ARTIFACT_DIR']}/{platform}/scan_logic.env")
    # mkdir
    Path(f"{os.environ['ARTIFACT_DIR']}/{platform}").mkdir(parents=True, exist_ok=True)

    with Path(f"{os.environ['ARTIFACT_DIR']}/{platform}/scan_logic.env").open(
        "w", encoding="utf-8"
    ) as f:
        f.writelines(
            [
                f"IMAGE_TO_SCAN={image_name_tag}\n",
                f"COMMIT_SHA_TO_SCAN={commit_sha}\n",
                f"DIGEST_TO_SCAN={digest}\n",
                f"BUILD_DATE_TO_SCAN={build_date}",
            ]
        )

    log.info(f"Writing {os.environ['ARTIFACT_DIR']}/{platform}/scan_logic.json")
    with Path(f"{os.environ['ARTIFACT_DIR']}/{platform}/scan_logic.json").open(
        "w", encoding="utf-8"
    ) as f:
        f.write(json.dumps({
            "IMAGE_TO_SCAN": image_name_tag,
            "COMMIT_SHA_TO_SCAN": commit_sha,
            "DIGEST_TO_SCAN": digest,
            "BUILD_DATE_TO_SCAN": build_date,
        }))

def parse_packages(sbom: Path | dict, access_log: Path | list[str]) -> list[Package]:
    """Verify sbom and access log files exist and parse packages
    accordingly."""
    # Pipeline should fail if sbom does not exist (exception not caught)
    pkgs = set(SbomFileParser.parse(sbom))

    access_log_exists = (
        access_log.exists() if isinstance(access_log, Path) else bool(access_log)
    )

    if access_log_exists:
        pkgs.update(AccessLogFileParser.parse(access_log))
    else:
        log.info("Access log does not exist")

    log.info("Packages parsed:")
    for pkg in pkgs:
        log.info(f"  {pkg}")
    return pkgs


def download_artifacts(image: Image, output_dir: Path, docker_config_dir: Path) -> bool:
    """Download cosign attestation and save predicates for sbom & hardening
    manifest to files."""
    try:
        log.info(f"Downloading artifacts for image: {image}")
        # Download syft sbom (json) & hardening manifest (json)
        Cosign.download(
            image,
            output_dir,
            docker_config_dir,
            [
                "https://github.com/anchore/syft#output-formats",
                "https://repo1.dso.mil/dsop/dccscr/-/raw/master/hardening%20manifest/README.md",
            ],
            log_cmd=True,
        )
        log.info(f"Artifacts downloaded to temp directory: {output_dir}")
    except CosignDownloadError as e:
        log.error(e)
        return False
    return True


def get_old_pkgs(
    image_name: str, image_digest: str, docker_config_dir: Path
) -> list[Package]:
    """Return list of packages parsed from old image sbom & access log."""
    old_img = Image(
        registry=os.environ["REGISTRY_PUBLISH_URL"],
        name=image_name,
        digest=image_digest,
    )

    with tempfile.TemporaryDirectory(prefix="COSIGN-") as cosign_download:
        if download_artifacts(
            image=old_img,
            output_dir=cosign_download,
            docker_config_dir=docker_config_dir,
        ):
            old_sbom = Path(cosign_download, "sbom-syft-json.json")

            # Parse access log from hardening manifest
            with Path(cosign_download, "hardening_manifest.json").open(
                "r", encoding="utf-8"
            ) as hardening_manifest:
                old_access_log = (
                    json.load(hardening_manifest).get("access_log", "").split("\n")
                )

            # prevent old_access_log from having single value of '' if access log is missing
            old_access_log = [] if old_access_log == [""] else old_access_log

            log.info("Parsing old packages")
            return parse_packages(old_sbom, old_access_log)

        log.info("Download attestations failed")
        return []


def scan_logic(platform, digest):
    image_name = os.environ["IMAGE_NAME"]
    image_name_tag = os.environ["IMAGE_FULLTAG"]
    new_sbom = Path(
        os.environ["ARTIFACT_STORAGE"], f"sbom/{platform}/sbom-syft-json.json"
    )
    new_access_log = Path(
        os.environ["ARTIFACT_STORAGE"], f"build/{platform}/access_log"
    )

    write_env_vars(
        image_name_tag,
        os.environ["CI_COMMIT_SHA"].lower(),
        digest,
        os.environ["BUILD_DATE"],
        platform,
    )
    log.info("New image name, tag, digest, and build date saved")

    log.info("Parsing new packages")
    new_pkgs = parse_packages(new_sbom, new_access_log)

    if os.environ.get("FORCE_SCAN_NEW_IMAGE"):
        log.info("Skip Logic: Force scan new image")
    elif os.environ["CI_COMMIT_BRANCH"] != "master":
        log.info("Skip Logic: Non-master branch")
    else:
        # STAGING_BASE_IMAGE not checked here - Only used for feature branches
        pull_auth = Path(os.environ["DOCKER_AUTH_FILE_PULL"])
        with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config_dir:
            shutil.copy(src=pull_auth, dst=Path(docker_config_dir, "config.json"))
            old_image_details = image_verify.diff_needed(docker_config_dir)
            if not old_image_details:
                log.info("Image verify failed - Must scan new image")
                sys.exit(0)

            log.info("SBOM diff required to determine image to scan")

            try:
                base_registry = os.environ["BASE_REGISTRY"]
                base_registry = base_registry.split("/")[0]
                with open(os.environ["DOCKER_AUTH_FILE_PULL"]) as f:
                    auth = json.load(f)
                encoded_credentials = auth['auths'][base_registry]['auth']
                headers = {
                    'Accept': 'application/json',
                    'Authorization': f'Basic {encoded_credentials}'
                }
                encoded_image_name = urllib.parse.quote(
                    image_name, safe=""
                )
                url = f"https://{base_registry}/api/v2.0/projects/ironbank/repositories/{encoded_image_name}/artifacts/{hardening_manifest.base_image_tag}"
                response = requests.get(url, headers=headers)
                response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes
                json_data = response.json()
            except requests.exceptions.RequestException as e:
                print(f"An error occurred: {e}")
                exit(1)
            if (
                json_data["manifest_media_type"]
                == "application/vnd.oci.image.index.v1+json"
            ):
                for image in json_data["references"]:
                    if image['platform']['architecture'] == platform:
                        digest = image["child_digest"]


            old_pkgs = get_old_pkgs(
                image_name=image_name,
                image_digest=digest, # Should just have to change this line.
                docker_config_dir=docker_config_dir,
            )
        if not old_pkgs:
            log.info("No old pkgs to compare - Must scan new image")
            sys.exit(0)

        if new_pkgs.symmetric_difference(old_pkgs):
            log.info(f"Packages added: {new_pkgs - old_pkgs}")
            log.info(f"Packages removed: {old_pkgs - new_pkgs}")
            log.info("Package(s) difference detected - Must scan new image")
        else:
            log.info("Package lists match - Able to scan old image")
            # Override image to scan with old tag
            image_name_tag = f"{os.environ['REGISTRY_PUBLISH_URL']}/{image_name}:{old_image_details['tag']}"
            write_env_vars(
                image_name_tag,
                old_image_details["commit_sha"],
                old_image_details["digest"],
                old_image_details["build_date"],
                platform,
            )
            log.info("Old image name, tag, digest, and build date saved")


def main():
    """Main function that performs package comparison between a new image and a
    previously scanned image.

    It fetches the new image's details from the environment, including its name, tag, digest, and build date.
    It then writes these details into an environment variable file using the `write_env_vars` function.

    The function also fetches the packages in the new image and checks if there are any differences
    between the packages in the new image and a previously scanned image. If differences are found,
    the function writes the old image details into the environment variable file.

    In certain scenarios such as when the image cannot be verified, when there are no old packages to
    compare, or when the new image is forced to be scanned, the function logs appropriate messages
    and continues to the next step or exits.

    Note:
    This function expects certain environment variables to be set. It can exit the program based on
    the evaluation of certain conditions.
    """

    potential_platforms = [
        "amd64",
        "arm64",
    ]

    platforms = [
        {
            "platform": platform,
            "digest": Path(
                f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/digest'
            ).read_text(),
        }
        for platform in potential_platforms
        if os.path.isfile(f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/digest')
    ]

    for platform in platforms:
        print(f"generating for {platform['platform']}..")
        scan_logic(platform["platform"], platform["digest"])


if __name__ == "__main__":
    main()
