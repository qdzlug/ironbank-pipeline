#!/usr/bin/env python3

# TODO: re-implement scanning previous
import base64
import json
import os
import shutil
import subprocess
import tempfile
import urllib
from pathlib import Path
from urllib.request import Request, urlopen

import image_verify
import requests
from common.utils import logger
from pipeline.container_tools.cosign import Cosign
from pipeline.file_parser import AccessLogFileParser, SbomFileParser
from pipeline.hardening_manifest import HardeningManifest
from pipeline.image import Image
from pipeline.project import DsopProject
from pipeline.utils.exceptions import CosignDownloadError
from pipeline.utils.types import Package

log = logger.setup("scan_logic_jobs")


def write_env_vars(scan: dict) -> None:
    """Writes environment variables into a file named 'scan_logic.env'.

    This function takes the image name and tag, commit SHA, image digest,
    and the build date. It then writes these as environment variables
    into a file named 'scan_logic.env' and 'scan_logic.json'.

    It also writes the various scanner and tool versions.

    Arguments:
    - build: the build json
    """
    # ANCHORE_VERSION
    anchore_auth = base64.b64encode(
        bytes(
            f'{os.environ["ANCHORE_USERNAME"]}:{os.environ["ANCHORE_PASSWORD"]}',
            "ascii",
        )
    )
    url = f'{os.environ["ANCHORE_URL"]}/version'
    headers = {"Authorization": f"Basic {anchore_auth.decode('utf-8')}"}

    # Open the URL and read the response
    with urlopen(Request(url, headers=headers)) as response:
        # Read the response data
        data = response.read().decode()

    # Parse the JSON response
    anchore_version = json.loads(data)["service"]["version"]

    # TODO: If the code above works delete me.
    # anchore_version = json.loads(
    #     urlopen(
    #         Request(
    #             f'{os.environ["ANCHORE_URL"]}/version',
    #             headers={"Authorization": f"Basic {anchore_auth.decode('utf-8')}"},
    #         )
    #     )
    #     .read()
    #     .decode()
    # )["service"]["version"]

    # GPG_VERSION
    gpg_version = (
        subprocess.check_output(["sh", "-c", "gpg --version"], text=True)
        .partition("\n")[0]
        .split(" ")[2]
    )

    # OPENSCAP_VERSION
    openscap_version = Path("/opt/oscap/version.txt").read_text().rstrip()

    # TWISTLOCK_VERSION
    twistlock_version = (
        subprocess.check_output(["sh", "-c", "twistcli --version"], text=True)
        .strip("\n")
        .split(" ")[2]
    )

    log.info(f"Writing {os.environ['ARTIFACT_DIR']}/{scan['PLATFORM']}/scan_logic.env")

    # mkdir
    Path(f"{os.environ['ARTIFACT_DIR']}/{scan['PLATFORM']}").mkdir(
        parents=True, exist_ok=True
    )

    with Path(f"{os.environ['ARTIFACT_DIR']}/{scan['PLATFORM']}/scan_logic.env").open(
        "w", encoding="utf-8"
    ) as f:
        f.writelines(
            [
                f"ANCHORE_VERSION={anchore_version}\n",
                f"BUILD_DATE_TO_SCAN={scan['BUILD_DATE']}\n",
                f"COMMIT_SHA_TO_SCAN={os.environ['CI_COMMIT_SHA']}\n",
                f"DIGEST_TO_SCAN={scan['DIGEST']}\n",
                f"GPG_VERSION={gpg_version}\n",
                f"IMAGE_TO_SCAN={scan['IMAGE_FULLTAG']}\n",
                f"OPENSCAP_VERSION={openscap_version}\n",
                f"TWISTLOCK_VERSION={twistlock_version}",
            ]
        )

    log.info(f"Writing {os.environ['ARTIFACT_DIR']}/{scan['PLATFORM']}/scan_logic.json")
    with Path(f"{os.environ['ARTIFACT_DIR']}/{scan['PLATFORM']}/scan_logic.json").open(
        "w", encoding="utf-8"
    ) as f:
        f.write(
            json.dumps(
                {
                    "ANCHORE_VERSION": anchore_version,
                    "BUILD_DATE_TO_SCAN": scan["BUILD_DATE"],
                    "COMMIT_SHA_TO_SCAN": os.environ["CI_COMMIT_SHA"],
                    "DIGEST_TO_SCAN": scan["DIGEST"],
                    "GPG_VERSION": gpg_version,
                    "IMAGE_TO_SCAN": scan["IMAGE_FULLTAG"],
                    "OPENSCAP_VERSION": openscap_version,
                    "TWISTLOCK_VERSION": twistlock_version,
                }
            )
        )


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


def scan_logic(build, platform):
    image_name = build["IMAGE_NAME"]

    new_sbom = Path(
        os.environ["ARTIFACT_STORAGE"], f"sbom/{build['PLATFORM']}/sbom-syft-json.json"
    )
    new_access_log = Path(
        os.environ["ARTIFACT_STORAGE"], f"build/{build['PLATFORM']}/access_log"
    )

    write_env_vars(build)
    log.info("New image name, tag, digest, and build date saved")

    log.info("Parsing new packages")
    new_pkgs = parse_packages(new_sbom, new_access_log)

    if os.environ.get("FORCE_SCAN_NEW_IMAGE"):
        log.info("Skip Logic: Force scan new image")
    elif os.environ["CI_COMMIT_BRANCH"] != "master":
        log.info("Skip Logic: Non-master branch")
    else:
        # STAGING_BASE_IMAGE not checked here - Only used for feature branches
        with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config_dir:
            shutil.copy(
                src=Path(os.environ["DOCKER_AUTH_FILE_PULL"]),
                dst=Path(docker_config_dir, "config.json"),
            )
            old_image_details = image_verify.diff_needed(
                docker_config_dir, build, platform
            )
            if old_image_details:
                log.info("SBOM diff required to determine image to scan")
                dsop_project = DsopProject()
                hardening_manifest = HardeningManifest(
                    dsop_project.hardening_manifest_path
                )
                if hardening_manifest.base_image_name:
                    tag = hardening_manifest.base_image_tag
                else:
                    tag = hardening_manifest.image_tag
                try:
                    base_registry = os.environ["BASE_REGISTRY"]
                    base_registry = base_registry.split("/")[0]
                    with open(os.environ["DOCKER_AUTH_FILE_PULL"]) as f:
                        auth = json.load(f)
                    encoded_credentials = auth["auths"][base_registry]["auth"]
                    headers = {
                        "Accept": "application/json",
                        "Authorization": f"Basic {encoded_credentials}",
                    }
                    encoded_image_name = urllib.parse.quote(image_name, safe="")
                    url = f"https://{base_registry}/api/v2.0/projects/ironbank/repositories/{encoded_image_name}/artifacts/{tag}"
                    response = requests.get(url, headers=headers)
                    response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes
                    json_data = response.json()
                except requests.exceptions.RequestException as e:
                    print(f"An error occurred: {e}")
                    exit(1)
                    # If it's a manifest list.
                if (
                    json_data["manifest_media_type"]
                    == "application/vnd.oci.image.index.v1+json"
                ):
                    for image in json_data["references"]:
                        if image["platform"]["architecture"] == build["PLATFORM"]:
                            digest = image["child_digest"]
                else:
                    digest = old_image_details["digest"]

                old_pkgs = get_old_pkgs(
                    image_name=image_name,
                    image_digest=digest,  # Should just have to change this line.
                    docker_config_dir=docker_config_dir,
                )

                if old_pkgs:
                    log.info("old pkgs to compare")
                    if new_pkgs.symmetric_difference(old_pkgs):
                        log.info(f"Packages added: {new_pkgs - old_pkgs}")
                        log.info(f"Packages removed: {old_pkgs - new_pkgs}")
                        log.info("Package(s) difference detected - Must scan new image")
                    else:
                        log.info("Package lists match - Able to scan old image")
                        # Override image to scan with old tag
                        image_name_tag = f"{os.environ['REGISTRY_PUBLISH_URL']}/{image_name}:{old_image_details['tag']}"
                        build.update(
                            {
                                "COMMIT_SHA_TO_SCAN": old_image_details["commit_sha"],
                                "BUILD_DATE_TO_SCAN": old_image_details["build_date"],
                                "DIGEST_TO_SCAN": old_image_details["digest"],
                                "IMAGE_TO_SCAN": image_name_tag,
                            }
                        )
                        write_env_vars(build)
                        log.info("Old image name, tag, digest, and build date saved")
                if not old_pkgs:
                    log.info("No old pkgs to compare - Must scan new image")
            else:
                log.info("Image verify failed - Must scan new image")


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
        platform
        for platform in potential_platforms
        if os.path.isfile(f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/digest')
    ]

    for platform in platforms:
        print(f"generating for {platform}..")

        # load platform build.json
        with open(f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/build.json') as f:
            build = json.load(f)

        scan_logic(build, platform)


if __name__ == "__main__":
    main()
