#!/usr/bin/env python3

import os
import sys
import json
import yaml
import base64
import hashlib
from pathlib import Path

from ironbank.pipeline.image import Image
from ironbank.pipeline.utils.predicates import (
    get_predicate_types,
    get_unattached_predicates,
)
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.utils import logger

from ironbank.pipeline.utils.exceptions import GenericSubprocessError

log = logger.setup("upload_to_harbor")


def compare_digests(image: Image) -> None:
    """
    Pull down image manifest to compare digest to digest from build environment
    """

    log.info("Pulling manifest_file with skopeo")
    skopeo = Skopeo("staging_auth.json")

    try:
        log.info("Inspecting image in registry")
        remote_inspect_raw = skopeo.inspect(
            image.from_image(transport="docker://"), raw=True, log_cmd=True
        )
    except GenericSubprocessError:
        log.error(
            f"Failed to retrieve manifest for {image.registry}/{image.name}@{image.digest}"
        )
        sys.exit(1)

    digest = os.environ["IMAGE_PODMAN_SHA"].split(":")[-1]
    manifest = hashlib.sha256(remote_inspect_raw.encode())

    if digest == manifest.hexdigest():
        log.info("Digests match")
    else:
        log.error(f"Digests do not match {digest}  {manifest.hexdigest()}")
        sys.exit(1)


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
        try:
            Skopeo.copy(
                staging_image,
                production_image,
                src_authfile="staging_auth.json",
                dest_authfile="/tmp/config.json",
                log_cmd=True,
            )
        except GenericSubprocessError:
            log.error(f"Failed to copy {staging_image} to {production_image}")
            sys.exit(1)


def convert_artifacts_to_hardening_manifest(predicates: list, hardening_manifest: Path):

    hm_object = yaml.safe_load(hardening_manifest.read_text())

    for item in predicates:
        hm_object[item.name] = ""
        with item.open("r", errors="replace") as f:
            hm_object[item.name] = f.read()

    with Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.json").open("w") as f:
        json.dump(hm_object, f)


def create_vat_response_attestation():
    # Load VAT response for this pipeline run, convert to list
    with Path(os.environ["VAT_RESPONSE"]).open("r") as f:
        pipeline_vat_response = json.load(f)

    # Initialize lineage_vat_response as a list, so we can append to it if parent_vat_response.json doesn't exist
    lineage_vat_response = []
    if (
        parent_vat_response_file := Path(
            os.environ["ARTIFACT_DIR"], "parent_vat_response.json"
        )
    ).exists():
        with parent_vat_response_file.open("r") as f:
            lineage_vat_response = json.load(f)
        # parent_vat_response.json will not be a list when we release this, make sure to convert it to one
        if not isinstance(lineage_vat_response, list):
            lineage_vat_response = [lineage_vat_response]

    lineage_vat_response += pipeline_vat_response
    vat_response_lineage_file = Path(
        os.environ["ARTIFACT_DIR"], "vat_response_lineage.json"
    )
    with vat_response_lineage_file.open("w"):
        json.dumps(lineage_vat_response)
    return vat_response_lineage_file


def main():
    if "pipeline-test-project" in os.environ["CI_PROJECT_DIR"] and not os.environ.get(
        "DOCKER_AUTH_CONFIG_TEST"
    ):
        log.warning(
            """
            Skipping Harbor Upload. Cannot push to Harbor when working with pipeline
            test projects unless DOCKER_AUTH_CONFIG_TEST is set...
            """
        )
        sys.exit(1)

    # Grab staging docker auth
    staging_auth = base64.b64decode(os.environ["DOCKER_AUTH_CONFIG_STAGING"]).decode(
        "utf-8"
    )
    Path("staging_auth.json").write_text(staging_auth)

    # Grab ironbank/ironbank-testing docker auth
    test_auth = os.environ.get("DOCKER_AUTH_CONFIG_TEST", "").strip()
    if test_auth:
        dest_auth = base64.b64decode(test_auth).decode("utf-8")
    else:
        dest_auth = base64.b64decode(os.environ["DOCKER_AUTH_CONFIG_PROD"]).decode(
            "utf-8"
        )
    Path("/tmp/config.json").write_text(dest_auth)

    staging_image = Image(
        registry=os.environ["REGISTRY_URL_STAGING"],
        name=os.environ["IMAGE_NAME"],
        digest=os.environ["IMAGE_PODMAN_SHA"],
        transport="docker://",
    )

    tags = []
    with Path(os.environ["ARTIFACT_STORAGE"], "lint", "tags.txt").open(mode="r") as f:
        for tag in f:
            tags.append(tag.strip())

    production_image = Image(
        registry=os.environ["REGISTRY_URL_PROD"],
        name=os.environ["IMAGE_NAME"],
        digest=os.environ["IMAGE_PODMAN_SHA"],
        transport="docker://",
    )

    cosign = Cosign()

    # Compare digests to ensure image integrity
    compare_digests(staging_image)

    # Transfer image from staging project to production project and tag
    promote_tags(staging_image, production_image, tags)

    log.info("Signing image")
    try:
        cosign.sign(production_image, log_cmd=True)
    except GenericSubprocessError:
        log.error(
            f"Failed to sign image: {production_image.registry}/{production_image.name}@{production_image.digest}"
        )

    hm_resources = [
        Path(os.environ["CI_PROJECT_DIR"], "LICENSE"),
        Path(os.environ["CI_PROJECT_DIR"], "README.md"),
        Path(os.environ["ACCESS_LOG_DIR"], "access_log"),
    ]
    # Convert non-empty artifacts to hardening manifest
    convert_artifacts_to_hardening_manifest(
        [res for res in hm_resources if res.stat().st_size != 0],
        Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.yaml"),
    )

    predicates = [
        Path(os.environ["SBOM_DIR"], file)
        for file in os.listdir(os.environ["SBOM_DIR"])
        if file not in get_unattached_predicates()
    ]
    predicates.append(Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.json"))

    predicates.append(create_vat_response_attestation())
    predicate_types = get_predicate_types()
    log.info("Adding attestations")
    for predicate in predicates:
        try:
            cosign.attest(
                image=production_image,
                predicate_path=predicate.as_posix(),
                predicate_type=predicate_types[predicate.name],
                replace=True,
                log_cmd=True,
            )
        except GenericSubprocessError:
            log.error(f"Failed to add attestation {predicate.as_posix()}")
            sys.exit(1)


if __name__ == "__main__":
    main()
