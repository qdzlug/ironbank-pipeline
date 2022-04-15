#!/usr/bin/env python3

import base64
import hashlib
import logging
import os
import pathlib
import subprocess
import sys
from dataclasses import dataclass

# https://github.com/anchore/syft#output-formats

# Defines a map of SBOM output formats provided by syft to their corresponding mediatypes
mime_types = {
    "sbom-json.json": "application/vnd.syft+json",
    "sbom-cyclonedx.xml": "application/vnd.cyclonedx+xml",
    "sbom-cyclonedx-json.json": "application/vnd.cyclonedx+json",
    "sbom-spdx.xml": "text/spdx",
    "sbom-spdx-json.json": "application/spdx+json",
    "sbom-spdx-tag-value.txt": "text/plain",
}


@dataclass
class Image:
    """
    The Image Dataclass contains commonly used image attributes
    """

    name: str
    registry: str
    digest: str


class Cosign:
    """
    Perform cosign operations
    """

    def __init__(
        self,
        image: Image,
        cosign_cert: str,
        kms_key_arn: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
    ):
        self.image = image
        self.cosign_cert = cosign_cert
        self.kms_key_arn = kms_key_arn
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key

    def sign_image(self) -> None:
        """
        Perform cosign image signature
        """
        logging.info(
            f"Signing {self.image.registry}/{self.image.name}@{self.image.digest}"
        )
        sign_cmd = [
            "cosign",
            "sign",
            "--key",
            self.kms_key_arn,
            "--cert",
            self.cosign_cert,
            f"{self.image.registry}/{self.image.name}@{self.image.digest}",
        ]
        logging.info(" ".join(sign_cmd))
        try:
            subprocess.run(
                args=sign_cmd,
                check=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "AWS_ACCESS_KEY_ID": self.aws_access_key_id,
                    "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key,
                    "AWS_REGION": "us-gov-west-1",
                    **os.environ,
                },
            )
        except subprocess.CalledProcessError:
            logging.error(
                f"Failed to sign image: {self.image.registry}/{self.image.name}@{self.image.digest}"
            )
            sys.exit(1)

    def sign_image_attachment(self, attachment_type) -> None:
        """
        Perform cosign image attachment signature
        """
        logging.info(
            f"Signing {self.image.registry}/{self.image.name}@{self.image.digest}"
        )
        sign_cmd = [
            "cosign",
            "sign",
            "--key",
            self.kms_key_arn,
            f"--attachment={attachment_type}",
            f"{self.image.registry}/{self.image.name}@{self.image.digest}",
        ]
        logging.info(" ".join(sign_cmd))
        try:
            subprocess.run(
                args=sign_cmd,
                check=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "AWS_ACCESS_KEY_ID": self.aws_access_key_id,
                    "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key,
                    "AWS_REGION": "us-gov-west-1",
                    **os.environ,
                },
            )
        except subprocess.CalledProcessError:
            logging.error(
                f"Failed to sign {attachment_type}: {self.image.registry}/{self.image.name}@{self.image.digest}"
            )
            sys.exit(1)

    def add_attestation(self, predicate_path: str, predicate_type: str) -> None:
        """
        Add attestation
        """
        logging.info(
            f"Pushing attestation {predicate_path} with type of {predicate_type}"
        )
        cmd = [
            "cosign",
            "attest",
            "--predicate",
            predicate_path,
            "--type",
            predicate_type,
            "--key",
            self.kms_key_arn,
            f"{self.image.registry}/{self.image.name}@{self.image.digest}",
        ]
        logging.info(" ".join(cmd))
        try:
            subprocess.run(
                args=cmd,
                check=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "AWS_ACCESS_KEY_ID": self.aws_access_key_id,
                    "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key,
                    "AWS_REGION": "us-gov-west-1",
                    **os.environ,
                },
            )
        except subprocess.CalledProcessError:
            logging.error(f"Failed to add attestation {predicate_path}")
            sys.exit(1)


def push_oras(image: Image) -> None:
    """
    Perform image SBOM push with Oras
    """

    logging.info("Push SBOM")
    os.chdir(os.environ["SBOM_DIR"])
    sboms = [f"{file}:{mime_types[file]}" for file in os.listdir(os.getcwd())]
    formatted_digest = image.digest.split(":")[1]
    logging.info(f"Pushing SBOM for {image.registry}/{image.name}@{image.digest}")
    sign_cmd = [
        "oras",
        "push",
        "--config",
        "/tmp/config.json",
        f"{image.registry}/{image.name}:sha256-{formatted_digest}.sbom",
        *sboms,
    ]

    logging.info(" ".join(sign_cmd))
    try:
        subprocess.run(
            args=sign_cmd,
            check=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.chdir(os.environ["CI_PROJECT_DIR"])
    except subprocess.CalledProcessError:
        logging.error(
            f"Failed to push SBOM for {image.registry}/{image.name}@{image.digest}"
        )
        sys.exit(1)


def compare_digests(image: Image) -> None:
    """
    Pull down image manifest to compare digest to digest from build environment
    """

    manifest_file = pathlib.Path("manifest.json")
    logging.info(f"Pulling {manifest_file} with skopeo")
    cmd = [
        "skopeo",
        "inspect",
        "--authfile",
        "staging_auth.json",
        "--raw",
        f"docker://{image.registry}/{image.name}@{image.digest}",
    ]
    logging.info(" ".join(cmd))
    with manifest_file.open(mode="w") as f:
        try:
            subprocess.run(
                args=cmd,
                stdout=f,
                check=True,
                encoding="utf-8",
            )
        except subprocess.CalledProcessError:
            logging.error(
                f"Failed to retrieve manifest for {image.registry}/{image.name}@{image.digest}"
            )
            sys.exit(1)

    digest = os.environ["IMAGE_PODMAN_SHA"].split(":")[-1]
    manifest = hashlib.sha256(manifest_file.read_bytes())

    if digest == manifest.hexdigest():
        logging.info("Digests match")
    else:
        logging.error(f"Digests do not match {digest}  {manifest.hexdigest()}")
        sys.exit(1)


def promote_tags(staging_image: Image, production_image: Image) -> None:
    """
    Promote image from staging project to production project,
    tagging it according the the tags defined in tags.txt
    """

    with pathlib.Path(os.environ["ARTIFACT_STORAGE"], "preflight", "tags.txt").open(
        mode="r"
    ) as f:
        for tag in f:
            tag = tag.strip()

            logging.info(
                f"Copy from staging to {production_image.registry}/{production_image.name}:{tag}"
            )
            cmd = [
                "skopeo",
                "copy",
                "--src-authfile",
                "staging_auth.json",
                "--dest-authfile",
                "/tmp/config.json",
                f"docker://{staging_image.registry}/{staging_image.name}@{staging_image.digest}",
                f"docker://{production_image.registry}/{production_image.name}:{tag}",
            ]
            try:
                subprocess.run(
                    args=cmd,
                    check=True,
                    encoding="utf-8",
                )
            except subprocess.CalledProcessError:
                logging.error(
                    f"""
                    Failed to copy
                    {staging_image.registry}/{staging_image.name}@{staging_image.digest}
                    to {production_image.registry}/{production_image.name}:{tag}
                    """
                )
                sys.exit(1)


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
        os.environ["IMAGE_NAME"],
        os.environ["STAGING_REGISTRY_URL"],
        os.environ["IMAGE_PODMAN_SHA"],
    )

    production_image = Image(
        os.environ["IMAGE_NAME"],
        os.environ["REGISTRY_URL"],
        os.environ["IMAGE_PODMAN_SHA"],
    )

    cosign = Cosign(
        production_image,
        os.environ["COSIGN_CERT"],
        os.environ["KMS_KEY_SHORT_ARN"],
        os.environ["COSIGN_AWS_ACCESS_KEY_ID"],
        os.environ["COSIGN_AWS_SECRET_ACCESS_KEY"],
    )

    # Compare digests to ensure image integrity
    compare_digests(staging_image)

    # Transfer image from staging project to production project and tag
    promote_tags(staging_image, production_image)

    logging.info("Signing image")
    # Sign image in registry with Cosign
    cosign.sign_image()

    # Create combined SBOM from SBOMs contained in the SBOM_DIR
    push_oras(production_image)

    # Push VAT response file as attestation
    cosign.add_attestation(
        os.environ["VAT_RESPONSE"],
        "https://vat.dso.mil/api/p1/predicate/beta1",
    )

    logging.info("Signing SBOM")
    cosign.sign_image_attachment("sbom")


if __name__ == "__main__":
    main()
