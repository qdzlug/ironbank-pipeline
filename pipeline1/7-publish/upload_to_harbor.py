#!/usr/bin/env python3

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import yaml
from common.utils import logger
from pipeline.container_tools.cosign import Cosign
from pipeline.container_tools.skopeo import Skopeo
from pipeline.hardening_manifest import HardeningManifest
from pipeline.image import Image
from pipeline.project import DsopProject
from pipeline.utils.decorators import (
    stack_trace_handler,
    subprocess_error_handler,
)
from pipeline.utils.exceptions import GenericSubprocessError
from pipeline.utils.predicates import Predicates

log = logger.setup("upload_to_harbor")


@subprocess_error_handler("Failed to retrieve manifest for staged image")
def compare_digests(image: Image, build) -> None:
    """Pull down image manifest to compare digest to digest from build
    environment."""

    log.info("Pulling manifest_file with skopeo")
    skopeo = Skopeo(Path(os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"]))

    log.info("Inspecting image in registry")
    remote_inspect_raw = skopeo.inspect(
        image.from_image(transport="docker://"), raw=True, log_cmd=True
    )

    digest = build["IMAGE_PODMAN_SHA"].split(":")[-1]
    manifest = hashlib.sha256(remote_inspect_raw.encode())

    if digest == manifest.hexdigest():
        log.info("Digests match")
    else:
        log.error(f"Digests do not match {digest}  {manifest.hexdigest()}")
        sys.exit(1)


@subprocess_error_handler(
    "Failed to copy image from staging project to production project"
)
def promote_tags(
    staging_image: Image, production_image: Image, tags: list[str]
) -> None:
    """Promote image from staging project to production project, tagging it
    according the the tags defined in tags.txt."""

    for tag in tags:
        tag = f"{tag}-{build['PLATFORM']}"
        production_image = production_image.from_image(tag=tag)

        log.info(f"Copy from staging to {production_image}")
        skopeo = Skopeo()
        skopeo.copy(
            staging_image,
            production_image,
            src_authfile=Path(os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"]),
            dest_authfile=Path(os.environ["DOCKER_AUTH_FILE_PUBLISH"]),
            log_cmd=True,
        )
        log.info(f"Successfully copied {staging_image} to {production_image}")


def _convert_artifacts_to_hardening_manifest(
    predicates: list, hardening_manifest: Path
):
    hm_object = yaml.safe_load(hardening_manifest.read_text())

    for item in predicates:
        hm_object[item.name] = ""
        with item.open("r", errors="replace") as f:
            hm_object[item.name] = f.read()

    with Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.json").open(
        "w", encoding="utf-8"
    ) as f:
        json.dump(hm_object, f)
        log.info("Converting artifacts to hardening manifest")


def _generate_vat_response_lineage_file():
    """Generates a VAT response lineage using *this* pipeline run's VAT
    response and the VAT response attestation from the parent image."""
    # Load VAT response for this pipeline run, convert to list
    with Path(
        os.environ["ARTIFACT_STORAGE"], "vat", build["PLATFORM"], "vat_response.json"
    ).open("r", encoding="utf-8") as f:
        pipeline_vat_response = json.load(f)

    # Initialize lineage_vat_response as a dict, so we can append to it if parent_vat_response.json doesn't exist
    lineage_vat_response = {"images": []}
    if (
        parent_vat_response_file := Path(
            os.environ["ARTIFACT_STORAGE"],
            "vat",
            build["PLATFORM"],
            "parent_vat_response.json",
        )
    ).exists():
        with parent_vat_response_file.open("r", encoding="utf-8") as f:
            log.info("parent VAT response exists")
            parent_vat_response = json.load(f)
            # parent_vat_response.json will not be a list when we release this, make sure to convert it to one
            lineage_vat_response["images"] += parent_vat_response.get("images") or [
                parent_vat_response
            ]
    lineage_vat_response["images"] += [pipeline_vat_response]

    Path(os.environ["ARTIFACT_DIR"], build["PLATFORM"]).mkdir(
        parents=True, exist_ok=True
    )

    lineage_vat_response_file = Path(
        os.environ["ARTIFACT_DIR"], build["PLATFORM"], "vat_response_lineage.json"
    )

    with lineage_vat_response_file.open("w", encoding="utf-8") as f:
        json.dump(lineage_vat_response, f)

    return lineage_vat_response_file


def generate_attestation_predicates(predicates):
    """Generates a list of predicates to be attached to the image as Cosign
    Attestations."""
    hm_resources = [
        Path(os.environ["CI_PROJECT_DIR"], "LICENSE"),
        Path(os.environ["CI_PROJECT_DIR"], "README.md"),
        Path(os.environ["ACCESS_LOG_DIR"], build["PLATFORM"], "access_log"),
    ]
    # Convert non-empty artifacts to hardening manifest
    _convert_artifacts_to_hardening_manifest(
        [res for res in hm_resources if res.stat().st_size != 0],
        Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.yaml"),
    )

    attestation_predicates = [
        Path(os.environ["SBOM_DIR"], build["PLATFORM"], file)
        for file in os.listdir(f'{os.environ["SBOM_DIR"]}/{build["PLATFORM"]}')
        if file not in predicates.unattached_predicates
    ]
    attestation_predicates.append(
        Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.json")
    )

    attestation_predicates.append(_generate_vat_response_lineage_file())
    return attestation_predicates


def write_env_vars(tags: list[str]) -> None:  # TODO: Write a unit test
    """Writes environment variables into a file named 'upload_to_harbor.env'.
    Used by the create-manifest-list job.
    """
    log.info("Writing env variables to file")
    tags_string = ",".join(tags)
    Path(os.environ["ARTIFACT_DIR"], build["PLATFORM"]).mkdir(
        parents=True, exist_ok=True
    )

    with Path(
        os.environ["ARTIFACT_DIR"], build["PLATFORM"], "upload_to_harbor.env"
    ).open("w", encoding="utf-8") as f:
        f.write(f"REGISTRY_PUBLISH_URL={os.environ['REGISTRY_PUBLISH_URL']}\n")
        f.write(f"IMAGE_NAME={build['IMAGE_NAME']}\n")
        f.write(f"DIGEST_TO_SCAN={scan_logic['DIGEST_TO_SCAN']}\n")
        f.write(f"TAGS={tags_string}\n")


@stack_trace_handler
def main():
    """Main function to perform image promotion, signing, and attestation
    process in a secure software supply chain.

    This function is responsible for the image handling process in a secure software supply chain. It promotes an image
    from staging to production, signs it and attests the image.

    The function creates the staging and production images based on environment variables, generates predicates for attestation,
    and sets up a temporary Docker configuration directory.

    It then compares the staging and production image digests to ensure image integrity, and if the image scanned was a
    new one, it promotes the image and tags from staging to production, then signs the image.

    Finally, the function attests the production image with all generated predicates.

    Environment Variables:
        REGISTRY_PRE_PUBLISH_URL (str): The registry url for staging image.
        IMAGE_NAME (str): The name of the image.
        IMAGE_PODMAN_SHA (str): The digest of the staging image.
        REGISTRY_PUBLISH_URL (str): The registry url for production image.
        DIGEST_TO_SCAN (str): The digest of the production image.
        DOCKER_AUTH_FILE_PUBLISH (str): The path to Docker authentication file for publishing.
        IMAGE_TO_SCAN (str): Indicates which image is being scanned.

    Raises:
        SystemExit: Exits the process if a GenericSubprocessError is raised, indicating a subprocess call failed.

    Returns:
        None
    """
    # staging image is always the new image
    staging_image = Image(
        registry=os.environ["REGISTRY_PRE_PUBLISH_URL"],
        name=build["IMAGE_NAME"],
        digest=build["IMAGE_PODMAN_SHA"],
        transport="docker://",
    )
    # production image will have a different digest depending on which image was scanned
    # sha will either be same as staging, or the old image's digest
    production_image = Image.from_image(
        staging_image,
        registry=os.environ["REGISTRY_PUBLISH_URL"],
        digest=scan_logic["DIGEST_TO_SCAN"],
    )
    project = DsopProject()
    hardening_manifest = HardeningManifest(project.hardening_manifest_path)
    predicates = Predicates()
    attestation_predicates = generate_attestation_predicates(predicates)

    try:
        # Compare digests to ensure image integrity
        compare_digests(staging_image, build)
        with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config_dir:
            shutil.copy(
                os.environ["DOCKER_AUTH_FILE_PUBLISH"],
                Path(docker_config_dir, "config.json"),
            )
            cosign = Cosign(docker_config_dir=docker_config_dir)
            # if the new image was scanned
            if "ironbank-staging" in scan_logic["IMAGE_TO_SCAN"]:
                # Promote image and tags from staging project
                promote_tags(
                    staging_image,
                    production_image,
                    hardening_manifest.image_tags,
                )
                # Sign image
                cosign.sign(production_image, log_cmd=True)
                log.info("Promoting images and tags from staging and signing image")
            log.info("Adding attestations")
            for predicate in attestation_predicates:
                cosign.attest(
                    image=production_image,
                    predicate_path=predicate.as_posix(),
                    predicate_type=predicates.types[predicate.name],
                    replace=True,
                    log_cmd=True,
                )
            write_env_vars(hardening_manifest.image_tags)
    except GenericSubprocessError:
        sys.exit(1)


def publish_vat_staging_predicates():
    """Publishes a VAT (Verified Access Token) on a staging image using the
    cosign tool.

    Reads various details from environment variables for this process. If the attestation fails,
    the function exits with a non-zero status code.

    Raises:
        GenericSubprocessError: If an error occurs during the cosign attest command.

    Returns:
        None
    """
    staging_image = Image(
        registry=os.environ["REGISTRY_PRE_PUBLISH_URL"],
        name=build["IMAGE_NAME"],
        digest=build["IMAGE_PODMAN_SHA"],
        transport="docker://",
    )

    predicates = Predicates()
    vat_predicate = _generate_vat_response_lineage_file()

    with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config_dir:
        shutil.copy(
            os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"],
            Path(docker_config_dir, "config.json"),
        )
        cosign = Cosign(docker_config_dir=docker_config_dir)
        try:
            cosign.attest(
                image=staging_image,
                predicate_path=vat_predicate.as_posix(),
                predicate_type=predicates.types[vat_predicate.name],
                replace=True,
                log_cmd=True,
            )
        except GenericSubprocessError:
            sys.exit(1)


if __name__ == "__main__":
    potential_platforms = [
        "amd64",
        "arm64",
    ]

    platforms = [
        platform
        for platform in potential_platforms
        if os.path.isfile(
            f'{os.environ["ARTIFACT_STORAGE"]}/scan-logic/{platform}/scan_logic.json'
        )
    ]

    for platform in platforms:
        # load platform build.json
        with open(f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/build.json') as f:
            build = json.load(f)

        # load platform scan_logic.json
        with open(
            f'{os.environ["ARTIFACT_STORAGE"]}/scan-logic/{platform}/scan_logic.json'
        ) as f:
            scan_logic = json.load(f)

        if os.environ.get("PUBLISH_VAT_STAGING_PREDICATES"):
            publish_vat_staging_predicates()
        else:
            main()
