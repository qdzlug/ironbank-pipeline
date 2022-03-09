#!/usr/bin/env python3

import base64

# import hashlib
import logging
import os
import pathlib

# import secrets
import subprocess
import sys

import requests


class Cosign:
    def __init__(self, image_name):
        self.image_name = image_name

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
            os.environ["AWS_KMS_KEY_ID"],
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
                    "AWS_ACCESS_KEY_ID": os.environ["S3_ACCESS_KEY"],
                    "AWS_SECRET_ACCESS_KEY": os.environ["S3_SECRET_KEY"],
                    **os.environ,
                },
            )
        except subprocess.CalledProcessError:
            logging.error(f"Failed to sign {self.image_name}")
            sys.exit(1)
        return

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
                env={
                    "AWS_ACCESS_KEY_ID": os.environ["S3_ACCESS_KEY"],
                    "AWS_SECRET_ACCESS_KEY": os.environ["S3_SECRET_KEY"],
                    **os.environ,
                },
            )
        except subprocess.CalledProcessError:
            logging.error(f"Failed to attach {sbom_path}")
            sys.exit(1)
        return


def query_delegation_key(url, token):
    """
    Query the delegation key url a few times to make sure there isn't any
    rate limiting or anything.

    """
    key = None
    logging.info(f"Querying {url}")
    for _ in range(int(os.environ.get("VAULT_RETRIES", 5))):
        r = requests.get(
            url=url,
            headers={
                "X-Vault-Request": "true",
                "X-Vault-Namespace": os.environ["VAULT_NAMESPACE"],
                "X-Vault-Token": token,
            },
        )
        if r.status_code == 200:
            key = r.json()["data"]["delegationkey"]
            break
        else:
            logging.info(f"[{r.status_code}] Key not retrieved, trying again.")
            # key remains None

    return key


def get_delegation_key():
    """
    Interaction with Vault. Log in and grab a session token and then use
    the session token to grab the delegation key to sign.

    """
    logging.info("Logging into vault")
    url = f"{os.environ['VAULT_ADDR']}/v1/auth/userpass/login/{os.environ['VAULT_USERNAME']}"

    token = None
    for _ in range(int(os.environ.get("VAULT_RETRIES", 5))):
        r = requests.put(
            url=url,
            data={"password": os.environ["VAULT_PASSWORD"]},
            headers={
                "X-Vault-Request": "true",
                "X-Vault-Namespace": os.environ["VAULT_NAMESPACE"],
            },
        )

        if r.status_code == 200:
            token = r.json()["auth"]["client_token"]
            break
        else:
            logging.error(f"[{r.status_code}] Could not log into vault, trying again.")
            # token remains None

    if not token:
        logging.error("Could not log into vault")
        logging.info(
            "If you are seeing 503, then please try setting VAULT_RETRIES to a higher number and rerunning your stage."
        )
        sys.exit(1)

    logging.info("Log in successful")

    key = None
    for rev in range(int(os.environ["NOTARY_DELEGATION_CURRENT_REVISION"]), -1, -1):
        url = f"{os.environ['VAULT_ADDR']}/v1/kv/il2/notary/pipeline/delegation/{rev}"
        key = query_delegation_key(url=url, token=token)
        if key:
            break
        # key remains None if no delegationkey was received

    if not key:
        logging.error(
            "Could not retrieve delegation key - Please speak to an Administrator"
        )
        sys.exit(1)

    logging.info("Retrieved key")
    return key


def main():
    # assert os.environ.get("NOTARY_AUTH")

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
    # trust_dir = "trust-dir-delegation/"

    # # Generated randomly and used in both `notary` commands
    # delegation_passphrase = secrets.token_urlsafe(32)

    # key = get_delegation_key()

    # # Import delegation key
    # cmd = [
    #     "notary",
    #     "--trustDir",
    #     trust_dir,
    #     "key",
    #     "import",
    #     "--role",
    #     "delegation",
    #     "--gun",
    #     gun,
    #     "/dev/stdin",
    # ]
    # logging.info(" ".join(cmd))
    # try:
    #     subprocess.run(
    #         args=cmd,
    #         input=key,
    #         check=True,
    #         encoding="utf-8",
    #         env={
    #             "NOTARY_DELEGATION_PASSPHRASE": delegation_passphrase,
    #             **os.environ,
    #         },
    #     )
    # except subprocess.CalledProcessError:
    #     logging.error(f"Failed to import key for {gun}")
    #     sys.exit(1)

    # logging.info("Key imported")

    # # Pull down image manifest to sign
    # manifest_file = pathlib.Path("manifest.json")
    # logging.info(f"Pulling {manifest_file} with skopeo")
    # cmd = [
    #     "skopeo",
    #     "inspect",
    #     "--authfile",
    #     "staging_auth.json",
    #     "--raw",
    #     staging_image,
    # ]
    # logging.info(" ".join(cmd))
    # with manifest_file.open(mode="w") as f:
    #     try:
    #         subprocess.run(
    #             args=cmd,
    #             stdout=f,
    #             check=True,
    #             encoding="utf-8",
    #         )
    #     except subprocess.CalledProcessError:
    #         logging.error(f"Failed to retrieve manifest for {gun}")
    #         sys.exit(1)

    # # Confirm digest matches sha of the manifest
    # digest = os.environ["IMAGE_PODMAN_SHA"].split(":")[-1]
    # manifest = hashlib.sha256(manifest_file.read_bytes())

    # if digest == manifest.hexdigest():
    #     logging.info("Digests match")
    # else:
    #     logging.error(f"Digests do not match {digest}  {manifest.hexdigest()}")
    #     sys.exit(1)

    # Sign and promote all tags
    with pathlib.Path(os.environ["ARTIFACT_STORAGE"], "preflight", "tags.txt").open(
        mode="r"
    ) as f:
        for tag in f:
            tag = tag.strip()
            # logging.info(f"Signing {manifest_file} with notary")

            #         cmd = [
            #             "notary",
            #             "--verbose",
            #             "--server",
            #             os.environ["NOTARY_URL"],
            #             "--trustDir",
            #             trust_dir,
            #             "add",
            #             "--roles",
            #             "targets/releases",
            #             "--publish",
            #             gun,
            #             tag,
            #             str(manifest_file),
            #         ]
            #         logging.info(" ".join(cmd))
            #         try:
            #             subprocess.run(
            #                 args=cmd,
            #                 check=True,
            #                 encoding="utf-8",
            #                 env={
            #                     "NOTARY_DELEGATION_PASSPHRASE": delegation_passphrase,
            #                     **os.environ,
            #                 },
            #             )
            #         except subprocess.CalledProcessError:
            #             logging.error(f"Failed to sign {gun}")
            #             sys.exit(1)

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
    image_name = f"{os.environ['REGISTRY_URL']}/{os.environ['IMAGE_NAME']}:{os.environ['IMAGE_TAG']}"

    cosign = Cosign(image_name)
    cosign.attach_sbom(f"{os.environ['SBOM_DIR']}/sbom/sbom-cyclonedx.xml", "cyclonedx")
    cosign.attach_sbom(f"{os.environ['SBOM_DIR']}/sbom/sbom-spdx-json.json", "spdx")
    cosign.sign_image()


if __name__ == "__main__":
    main()
