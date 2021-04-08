#!/usr/bin/env python3

import base64
import hashlib
import logging
import os
import pathlib
import secrets
import subprocess
import sys

import requests


def query_delegation_key(url, token):
    """
    Query the delegation key url a few times to make sure there isn't any
    rate limiting or anything.

    """
    key = None
    logging.info(f"Querying {url}")
    for _ in range(5):
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
            logging.info(f"{r.status_code} - Key not found, trying again.")
            # key remains None

    return key


def get_delegation_key():
    """
    Interaction with Vault. Log in and grab a session token and then use
    the session token to grab the delegation key to sign.

    """
    logging.info("Logging into vault")
    url = f"{os.environ['VAULT_ADDR']}/v1/auth/userpass/login/{os.environ['VAULT_USERNAME']}"

    r = requests.put(
        url=url,
        data={"password": os.environ["VAULT_PASSWORD"]},
        headers={
            "X-Vault-Request": "true",
            "X-Vault-Namespace": os.environ["VAULT_NAMESPACE"],
        },
    )

    if r.status_code != 200:
        logging.error(f"[{r.status_code}] Could not log into vault")
        sys.exit(1)

    logging.info("Log in successful")
    token = r.json()["auth"]["client_token"]

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
    assert os.environ.get("NOTARY_AUTH")

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

    os.environ["NOTARY_DELEGATION_PASSPHRASE"] = secrets.token_urlsafe(32)

    if "pipeline-test-project" in os.environ["CI_PROJECT_DIR"] and not os.environ.get(
        "DOCKER_AUTH_CONFIG_TEST"
    ):
        logging.warning(
            "Skipping Harbor Upload. Cannot push to Harbor when working with pipeline test projects unless DOCKER_AUTH_CONFIG_TEST is set..."
        )
        sys.exit(1)

    staging_auth = base64.b64decode(os.environ["DOCKER_AUTH_CONFIG_STAGING"]).decode(
        "utf-8"
    )
    pathlib.Path("staging_auth.json").write_text(staging_auth)

    staging_image = f"{os.environ['STAGING_REGISTRY_URL']}/{os.environ['IMAGE_NAME']}"
    gun = f"{os.environ['REGISTRY_URL']}/{os.environ['IMAGE_NAME']}"

    key = get_delegation_key()

    trust_dir = "trust-dir-delegation/"

    cmd = [
        "notary",
        "--trustDir",
        trust_dir,
        "key",
        "import",
        "--role",
        "delegation",
        "--gun",
        gun,
        "/dev/stdin",
    ]
    logging.info(" ".join(cmd))
    try:
        subprocess.run(
            args=cmd,
            input=key,
            check=True,
            encoding="utf-8",
        )
    except subprocess.CalledProcessError:
        logging.error(f"Failed to import key for {gun}")
        sys.exit(1)

    logging.info("Key imported")

    test_auth = os.environ.get("DOCKER_AUTH_CONFIG_TEST", "").strip()
    if test_auth:
        dest_auth = base64.b64decode(test_auth).decode("utf-8")
    else:
        dest_auth = base64.b64decode(os.environ["DOCKER_AUTH_CONFIG_PROD"]).decode(
            "utf-8"
        )

    pathlib.Path("dest_auth.json").write_text(dest_auth)

    with pathlib.Path(os.environ["ARTIFACT_STORAGE"], "preflight", "tags.txt").open(
        mode="r"
    ) as f:
        for tag in f:
            tag = tag.strip()
            manifest_file = pathlib.Path(f"{tag}_manifest.json")
            cmd = [
                "skopeo",
                "inspect",
                "--authfile",
                "staging_auth.json",
                "--raw",
                f"docker://{staging_image}@{os.environ['IMAGE_PODMAN_SHA']}",
            ]

            logging.info(f"Pulling {manifest_file} with skopeo")
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

            digest = os.environ["IMAGE_PODMAN_SHA"].split(":")[-1]

            manifest = hashlib.sha256(manifest_file.read_bytes())

            if digest == manifest.hexdigest():
                logging.info("Digests match")
            else:
                logging.error(f"Digests do not match {digest}  {manifest.hexdigest()}")
                sys.exit(1)

            logging.info(f"Signing {manifest_file} with notary")

            p = subprocess.run(
                [
                    "notary",
                    "--verbose",
                    "--server",
                    os.environ["NOTARY_URL"],
                    "--trustDir",
                    trust_dir,
                    "add",
                    "--roles",
                    "targets/releases",
                    "--publish",
                    gun,
                    tag,
                    manifest_file,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
            )

            if p.returncode != 0:
                logging.error(p.stdout)
                logging.error(p.stderr)
                logging.error(f"Failed to import key for {gun}")
                sys.exit(p.returncode)

            logging.info(p.stdout)
            logging.info(f"Copy from staging to {gun}:{tag}")

            p = subprocess.run(
                [
                    "skopeo",
                    "copy",
                    "--src-authfile",
                    "staging_auth.json",
                    "--dest-authfile",
                    "dest_auth.json",
                    f"docker://{staging_image}@{os.environ['IMAGE_PODMAN_SHA']}",
                    f"docker://{gun}:{tag}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
            )

            if p.returncode != 0:
                logging.error(p.stdout)
                logging.error(p.stderr)
                logging.error(f"Failed to import key for {gun}")
                sys.exit(p.returncode)

            logging.info(p.stdout)


if __name__ == "__main__":
    main()
