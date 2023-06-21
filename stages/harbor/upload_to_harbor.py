#!/usr/bin/env python3

import os
import sys
import json
import yaml
import hashlib
import tempfile
import shutil
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
    """Pull down image manifest to compare digest to digest from build
    environment."""

    log.info("Pulling manifest_file with skopeo")
    skopeo = Skopeo(Path(os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"]))

    log.info("Inspecting image in registry")
    remote_inspect_raw = skopeo.inspect(
        image.from_image(transport="docker://"), raw=True, log_cmd=True
    )

    digest = os.environ["IMAGE_PODMAN_SHA"].split(":")[-1]
    manifest = hashlib.sha256(remote_inspect_raw.encode())
    log.info("digest")
    log.info(digest)
    log.info("manifest")
    log.info(manifest)

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

    log.info("HERE!!!! ")
    for tag in tags:
        production_image = production_image.from_image(tag=tag)
        log.info("HERE!!!! ")
        log.info(production_image)
        log.info("Copy from staging to {production_image}")
        Skopeo.copy(
            src=staging_image,
            dest=production_image,
            src_authfile=Path(os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"]),
            dest_authfile=Path(os.environ["DOCKER_AUTH_FILE_PUBLISH"]),
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

    with Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.json").open(
        "w", encoding="utf-8"
    ) as f:
        json.dump(hm_object, f)


def _generate_vat_response_lineage_file():
    """Generates a VAT response lineage using *this* pipeline run's VAT
    response and the VAT response attestation from the parent image."""
    # Load VAT response for this pipeline run, convert to list
    with Path(os.environ["VAT_RESPONSE"]).open("r", encoding="utf-8") as f:
        pipeline_vat_response = json.load(f)

    # Initialize lineage_vat_response as a dict, so we can append to it if parent_vat_response.json doesn't exist
    lineage_vat_response = {"images": []}
    if (parent_vat_response_file := Path(os.environ["PARENT_VAT_RESPONSE"])).exists():
        with parent_vat_response_file.open("r", encoding="utf-8") as f:
            parent_vat_response = json.load(f)

            # parent_vat_response.json will not be a list when we release this, make sure to convert it to one
            lineage_vat_response["images"] += parent_vat_response.get("images") or [
                parent_vat_response
            ]
    lineage_vat_response["images"] += [pipeline_vat_response]
    lineage_vat_response_file = Path(
        os.environ["ARTIFACT_DIR"], "vat_response_lineage.json"
    )
    with lineage_vat_response_file.open("w", encoding="utf-8") as f:
        json.dump(lineage_vat_response, f)

    log.info("Generated VAT response lineage file")
    return lineage_vat_response_file


def generate_attestation_predicates(predicates):
    """Generates a list of predicates to be attached to the image as Cosign
    Attestations."""
    log.info(predicates)
    hm_resources = [
        Path(os.environ["CI_PROJECT_DIR"], "LICENSE"),
        Path(os.environ["CI_PROJECT_DIR"], "README.md"),
        Path(os.environ["ACCESS_LOG_DIR"], "access_log"),
    ]

    # Predicates(types={'sbom-cyclonedx-json.json': 'cyclonedx',
    # 'sbom-spdx.xml': 'spdx', 'sbom-spdx-json.json': 'spdxjson',
    # 'sbom-syft-json.json': 'https://github.com/anchore/syft#output-formats',
    # 'vat_response_lineage.json': 'https://vat.dso.mil/api/p1/predicate/beta1',
    # 'hardening_manifest.json':
    # 'https://repo1.dso.mil/dsop/dccscr/-/raw/master/hardening%20manifest/README.md'},
    # unattached_predicates=['sbom-spdx-tag-value.txt', 'sbom-cyclonedx.xml'])

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
    # staging image is always the new image
    staging_image = Image(
        registry=os.environ["REGISTRY_PRE_PUBLISH_URL"],
        name=os.environ["IMAGE_NAME"],
        digest=os.environ["IMAGE_PODMAN_SHA"],
        transport="docker://",
    )
    # production image will have a different digest depending on which image was scanned
    # sha will either be same as staging, or the old image's digest
    production_image = Image.from_image(
        staging_image,
        registry=os.environ["REGISTRY_PUBLISH_URL"],
        digest=os.environ["DIGEST_TO_SCAN"],
    )
    project = DsopProject()
    hm = HardeningManifest(project.hardening_manifest_path)
    predicates = Predicates()
    attestation_predicates = generate_attestation_predicates(predicates)

    try:
        # Compare digests to ensure image integrity
        compare_digests(staging_image)
        with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config_dir:
            shutil.copy(
                os.environ["DOCKER_AUTH_FILE_PUBLISH"],
                Path(docker_config_dir, "config.json"),
            )
            cosign = Cosign(docker_config_dir=docker_config_dir)
            # if the new image was scanned
            if "ironbank-staging" in os.environ["IMAGE_TO_SCAN"]:
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
