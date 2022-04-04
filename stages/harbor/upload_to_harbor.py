#!/usr/bin/env python3

import base64
import hashlib
import logging
import os
import pathlib
import subprocess
import sys


class Cosign:
    """
    Perform cosign operations
    """

    def __init__(
        self,
        image_name: str,
        kms_key_arn: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
    ):
        self.image_name = image_name
        self.kms_key_arn = kms_key_arn
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key

    def sign_image(self) -> None:
        """
        Perform cosign image signature
        """
        logging.info(f"Signing {self.image_name}")
        sign_cmd = [
            "cosign",
            "--verbose",
            "sign",
            "--key",
            self.kms_key_arn,
            "--cert",
            os.environ["COSIGN_CERT"],
            self.image_name,
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
            logging.exception(f"Failed to sign {self.image_name}")
            sys.exit(1)


    def attach_sbom(self, sbom_path: str, sbom_type: str) -> None:
        """
        Sign and attach SBOMs
        """
        logging.info(f"Attaching SBOM: {sbom_path}")
        attach_cmd = [
            "cosign",
            "attach",
            "sbom",
            "--sbom",
            sbom_path,
            "--type",
            sbom_type,
            self.image_name,
        ]
        logging.info(" ".join(attach_cmd))
        try:
            subprocess.run(
                args=attach_cmd,
                check=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError:
            logging.error(f"Failed to attach {sbom_path}")
            sys.exit(1)

    def sign_image_attachment(self) -> None:
        """
        Perform cosign image attachment signature
        """
        logging.info(f"Signing {self.image_name}")
        sign_cmd = [
            "cosign",
            "--verbose",
            "sign",
            "--key",
            self.kms_key_arn,
            "--attachment=sbom",
            self.image_name,
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
            logging.exception(f"Failed to sign {self.image_name}")
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
            "Skipping Harbor Upload. Cannot push to Harbor when working with pipeline test projects unless DOCKER_AUTH_CONFIG_TEST is set..."
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
    pathlib.Path("dest_auth.json").write_text(dest_auth)
    pathlib.Path("/tmp/config.json").write_text(dest_auth)

    staging_image = f"docker://{os.environ['STAGING_REGISTRY_URL']}/{os.environ['IMAGE_NAME']}@{os.environ['IMAGE_PODMAN_SHA']}"
    gun = f"{os.environ['REGISTRY_URL']}/{os.environ['IMAGE_NAME']}"

    # Pull down image manifest to sign
    manifest_file = pathlib.Path("manifest.json")
    logging.info(f"Pulling {manifest_file} with skopeo")
    cmd = [
        "skopeo",
        "inspect",
        "--authfile",
        "staging_auth.json",
        "--raw",
        staging_image,
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
            logging.error(f"Failed to retrieve manifest for {gun}")
            sys.exit(1)

    # Confirm digest matches sha of the manifest
    digest = os.environ["IMAGE_PODMAN_SHA"].split(":")[-1]
    manifest = hashlib.sha256(manifest_file.read_bytes())

    if digest == manifest.hexdigest():
        logging.info("Digests match")
    else:
        logging.error(f"Digests do not match {digest}  {manifest.hexdigest()}")
        sys.exit(1)

    # Promote all tags
    with pathlib.Path(os.environ["ARTIFACT_STORAGE"], "preflight", "tags.txt").open(
        mode="r"
    ) as f:
        for tag in f:
            tag = tag.strip()

            logging.info(f"Copy from staging to {gun}:{tag}")
            prod_image = f"docker://{gun}:{tag}"
            cmd = [
                "skopeo",
                "copy",
                "--src-authfile",
                "staging_auth.json",
                "--dest-authfile",
                "dest_auth.json",
                staging_image,
                prod_image,
            ]
            try:
                subprocess.run(
                    args=cmd,
                    check=True,
                    encoding="utf-8",
                )
            except subprocess.CalledProcessError:
                logging.error(f"Failed to copy {staging_image} to {prod_image}")
                sys.exit(1)

    logging.info("Run cosign commands")
    image_name = f"{os.environ['REGISTRY_URL']}/{os.environ['IMAGE_NAME']}@{os.environ['IMAGE_PODMAN_SHA']}"

    cosign = Cosign(
        image_name,
        # TODO: update to full ARN once cosign allows for us-gov ARNs
        os.environ["KMS_KEY_SHORT_ARN"],
        os.environ["COSIGN_AWS_ACCESS_KEY_ID"],
        os.environ["COSIGN_AWS_SECRET_ACCESS_KEY"],
    )
    cosign.sign_image()
    cosign.attach_sbom(f"{os.environ['SBOM_DIR']}/sbom-syft-json.json", "syft")
    # Cosign doesn't currently support combining SBOMs into a single artifact
    # cosign.attach_sbom(f"{os.environ['SBOM_DIR']}/sbom-cyclonedx.xml", "cyclonedx")
    # cosign.attach_sbom(f"{os.environ['SBOM_DIR']}/sbom-spdx-json.json", "spdx")
    cosign.sign_image_attachment()


if __name__ == "__main__":
    main()
