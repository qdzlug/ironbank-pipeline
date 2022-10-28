#!/usr/bin/env python3

import os
import sys
import json
import yaml
import base64
import hashlib
import logging
import pathlib

from ironbank.pipeline.image import Image
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.container_tools.cosign import Cosign

from ironbank.pipeline.utils.exceptions import GenericSubprocessError

# https://github.com/anchore/syft#output-formats

# Defines a map of SBOM output formats provided by syft to their corresponding mediatypes
predicate_types = {
    "sbom-cyclonedx-json.json": "cyclonedx",
    "sbom-spdx.xml": "spdx",
    "sbom-spdx-json.json": "spdxjson",
    "sbom-syft-json.json": "https://github.com/anchore/syft#output-formats",
    "vat_response.json": "https://vat.dso.mil/api/p1/predicate/beta1",
    "hardening_manifest.json": "https://repo1.dso.mil/dsop/dccscr/-/raw/master/hardening%20manifest/README.md",
}

unattached_predicates = [
    "sbom-spdx-tag-value.txt",
    "sbom-cyclonedx.xml",
]


def compare_digests(image: Image) -> None:
    """
    Pull down image manifest to compare digest to digest from build environment
    """

    logging.info("Pulling manifest_file with skopeo")
    skopeo = Skopeo("staging_auth.json")

    try:
        logging.info("Inspecting image in registry")
        remote_inspect_raw = skopeo.inspect(
            image.from_image(transport="docker://"), raw=True
        )
    except GenericSubprocessError:
        logging.error(
            f"Failed to retrieve manifest for {image.registry}/{image.name}@{image.digest}"
        )
        sys.exit(1)

    digest = os.environ["IMAGE_PODMAN_SHA"].split(":")[-1]
    manifest = hashlib.sha256(remote_inspect_raw.encode())

    if digest == manifest.hexdigest():
        logging.info("Digests match")
    else:
        logging.error(f"Digests do not match {digest}  {manifest.hexdigest()}")
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

        logging.info(f"Copy from staging to {production_image}")
        try:
            Skopeo.copy(
                staging_image,
                production_image,
                src_authfile="staging_auth.json",
                dest_authfile="/tmp/config.json",
            )
        except GenericSubprocessError:
            logging.error(f"Failed to copy {staging_image} to {production_image}")
            sys.exit(1)


def convert_artifacts_to_hardening_manifest(
    predicates: list, hardening_manifest: pathlib.Path
):

    hm_object = yaml.safe_load(hardening_manifest.read_text())

    for item in predicates:
        hm_object[item.name] = ""
        with item.open("r", errors="replace") as f:
            hm_object[item.name] = f.read()

    with pathlib.Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.json").open(
        "w"
    ) as f:
        json.dump(hm_object, f)


def main():
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")

    if "pipeline-test-project" in os.environ["CI_PROJECT_DIR"] and not os.environ.get(
        "DOCKER_AUTH_CONFIG_TEST"
    ):
        logging.warning(
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
    pathlib.Path("staging_auth.json").write_text(staging_auth)

    # Grab ironbank/ironbank-testing docker auth
    test_auth = os.environ.get("DOCKER_AUTH_CONFIG_TEST", "").strip()
    if test_auth:
        dest_auth = base64.b64decode(test_auth).decode("utf-8")
    else:
        dest_auth = base64.b64decode(os.environ["DOCKER_AUTH_CONFIG_PROD"]).decode(
            "utf-8"
        )
    pathlib.Path("/tmp/config.json").write_text(dest_auth)

    staging_image = Image(
        registry=os.environ["REGISTRY_URL_STAGING"],
        name=os.environ["IMAGE_NAME"],
        digest=os.environ["IMAGE_PODMAN_SHA"],
        transport="docker://",
    )

    tags = []
    with pathlib.Path(os.environ["ARTIFACT_STORAGE"], "lint", "tags.txt").open(
        mode="r"
    ) as f:
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

    logging.info("Signing image")
    try:
        cosign.sign(production_image)
    except GenericSubprocessError:
        logging.error(
            f"Failed to sign image: {production_image.registry}/{production_image.name}@{production_image.digest}"
        )

    hm_resources = [
        pathlib.Path(os.environ["CI_PROJECT_DIR"], "LICENSE"),
        pathlib.Path(os.environ["CI_PROJECT_DIR"], "README.md"),
        pathlib.Path(os.environ["ACCESS_LOG_DIR"], "access_log"),
    ]
    # Convert non-empty artifacts to hardening manifest
    convert_artifacts_to_hardening_manifest(
        [res for res in hm_resources if res.stat().st_size != 0],
        pathlib.Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.yaml"),
    )

    predicates = [
        pathlib.Path(os.environ["SBOM_DIR"], file)
        for file in os.listdir(os.environ["SBOM_DIR"])
        if file not in unattached_predicates
    ]
    predicates.append(
        pathlib.Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.json")
    )
    predicates.append(pathlib.Path(os.environ["VAT_RESPONSE"]))

    logging.info("Adding attestations")
    for predicate in predicates:
        try:
            cosign.attest(
                image=production_image,
                predicate_path=predicate.as_posix(),
                predicate_type=predicate_types[predicate.name],
                replace=True,
            )
        except GenericSubprocessError:
            logging.error(f"Failed to add attestation {predicate.as_posix()}")
            sys.exit(1)


if __name__ == "__main__":
    main()
