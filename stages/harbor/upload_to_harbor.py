#!/usr/bin/env python3

import os
import sys
import json
import yaml
import hashlib
from pathlib import Path

from ironbank.pipeline.image import Image
from ironbank.pipeline.utils.predicates import Predicates
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.decorators import subprocess_error_handler
from ironbank.pipeline.utils.exceptions import GenericSubprocessError
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.project import DsopProject

log = logger.setup("upload_to_harbor")


@subprocess_error_handler("Failed to retrieve manifest for staged image")
def compare_digests(image: Image) -> None:
    """
    Pull down image manifest to compare digest to digest from build environment
    """

    log.info("Pulling manifest_file with skopeo")
    skopeo = Skopeo(Path(os.environ["DOCKER_AUTH_CONFIG_FILE_STAGING"]))

    log.info("Inspecting image in registry")
    remote_inspect_raw = skopeo.inspect(
        image.from_image(transport="docker://"), raw=True, log_cmd=True
    )

    digest = os.environ["IMAGE_PODMAN_SHA"].split(":")[-1]
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
    """
    Promote image from staging project to production project,
    tagging it according the the tags defined in tags.txt
    """

    for tag in tags:
        production_image = production_image.from_image(tag=tag)

        log.info(f"Copy from staging to {production_image}")
        Skopeo.copy(
            staging_image,
            production_image,
            src_authfile=Path(os.environ["DOCKER_AUTH_CONFIG_FILE_STAGING"]),
            dest_authfile=Path(os.environ["DOCKER_AUTH_CONFIG_FILE_PROD"]),
            log_cmd=True,
        )


def _convert_artifacts_to_hardening_manifest(
    predicates: list, hardening_manifest: Path
):

    hm_object = yaml.safe_load(hardening_manifest.read_text())

    for item in predicates:
        hm_object[item.name] = ""
        with item.open("r", errors="replace") as f:
            hm_object[item.name] = f.read()

    with Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.json").open("w") as f:
        json.dump(hm_object, f)


def _generate_vat_response_lineage_file():
    """
    Generates a VAT response lineage using *this* pipeline run's VAT response and the VAT response attestation from the parent image
    """
    # Load VAT response for this pipeline run, convert to list
    with Path(os.environ["VAT_RESPONSE"]).open("r") as f:
        pipeline_vat_response = json.load(f)

    # Initialize lineage_vat_response as a list, so we can append to it if parent_vat_response.json doesn't exist
    lineage_vat_response = []
    if (
        parent_vat_response_file := Path(
            os.environ["VAT_ARTIFACT_DIR"], "parent_vat_response.json"
        )
    ).exists():
        with parent_vat_response_file.open("r") as f:
            lineage_vat_response = json.load(f)
        # parent_vat_response.json will not be a list when we release this, make sure to convert it to one
        if not isinstance(lineage_vat_response, list):
            lineage_vat_response = [lineage_vat_response]

    lineage_vat_response += pipeline_vat_response
    lineage_vat_response_file = Path(
        os.environ["ARTIFACT_DIR"], "vat_response_lineage.json"
    )
    with lineage_vat_response_file.open("w"):
        json.dumps(lineage_vat_response)

    return lineage_vat_response_file


def generate_attestation_predicates(predicates):
    """
    Generates a list of predicates to be attached to the image as Cosign Attestations
    """
    hm_resources = [
        Path(os.environ["CI_PROJECT_DIR"], "LICENSE"),
        Path(os.environ["CI_PROJECT_DIR"], "README.md"),
        Path(os.environ["ACCESS_LOG_DIR"], "access_log"),
    ]
    # Convert non-empty artifacts to hardening manifest
    _convert_artifacts_to_hardening_manifest(
        [res for res in hm_resources if res.stat().st_size != 0],
        Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.yaml"),
    )

    attestation_predicates = [
        Path(os.environ["SBOM_DIR"], file)
        for file in os.listdir(os.environ["SBOM_DIR"])
        if file not in predicates.unattached_predicates
    ]
    attestation_predicates.append(
        Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.json")
    )

    attestation_predicates.append(_generate_vat_response_lineage_file())
    return attestation_predicates


def main():
    staging_image = Image(
        registry=os.environ["REGISTRY_URL_STAGING"],
        name=os.environ["IMAGE_NAME"],
        digest=os.environ["IMAGE_PODMAN_SHA"],
        transport="docker://",
    )
    production_image = Image.from_image(
        staging_image, registry=os.environ["REGISTRY_URL_PROD"]
    )
    project = DsopProject()
    hm = HardeningManifest(project.hardening_manifest_path)
    cosign = Cosign()
    predicates = Predicates()
    attestation_predicates = generate_attestation_predicates(predicates)

    try:
        # Compare digests to ensure image integrity
        compare_digests(staging_image)
        # Promote image and tags from staging project
        promote_tags(staging_image, production_image, hm.image_tags)
        # Sign image
        cosign.sign(production_image, log_cmd=True)
        log.info("Adding attestations")
        for predicate in attestation_predicates:
            cosign.attest(
                image=production_image,
                predicate_path=predicate.as_posix(),
                predicate_type=predicates.types[predicate.name],
                replace=True,
                log_cmd=True,
            )
    except GenericSubprocessError:
        sys.exit(1)


if __name__ == "__main__":
    main()
