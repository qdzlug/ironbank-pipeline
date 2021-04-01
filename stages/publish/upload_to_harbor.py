#!/usr/bin/env python3

import sys
import hashlib
import subprocess
import pathlib
import requests
import logging
import base64
import os

from requests import status_codes


def get_delegation_key(gun):
    logging.info("Logging into vault")
    url = f"{os.environ['VAULT_ADDR']}/v1/auth/userpass/login/{os.environ['VAULT_STAGING_USERNAME']}"

    r = requests.put(
        url=url,
        data={"password": os.environ["VAULT_STAGING_PASSWORD"]},
        headers={
            "X-Vault-Request": "true",
            "X-Vault-Namespace": os.environ["VAULT_NAMESPACE"],
        },
    )

    if r.status_code != 200:
        logging.error("Could not log into vault")
        logging.error(f"Vault returned {r.status_code}")
        sys.exit(1)

    logging.info("Log in successful")
    token = r.json()["auth"]["client_token"]

    key = None
    for rev in range(int(os.environ["NOTARY_DELEGATION_CURRENT_REVISION"]), -1, -1):
        url = f"{os.environ['VAULT_ADDR']}/v1/kv/il2/notary/pipeline/data/delegation-test/{rev}"
        logging.info(url)
        r = requests.get(
            url=url,
            headers={
                "X-Vault-Request": "true",
                "X-Vault-Namespace": os.environ["VAULT_NAMESPACE"],
                "X-Vault-Token": token,
            },
        )
        if r.status_code == 404:
            logging.info("Not found, looping")
            continue
        elif r.status_code == 200:
            key = r.json()["data"]["data"]["delegationkey"]
            break

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

    p = subprocess.run(
        ["openssl", "rand", "-base64", "32"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    if p.returncode != 0:
        logging.error(p.stdout)
        logging.error(p.stderr)
        sys.exit(p.returncode)

    os.environ["NOTARY_DELEGATION_PASSPHRASE"] = p.stdout

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

    staging_image = f"{os.environ['STAGING_REGISTRY_URL']}/{os.environ['IM_NAME']}"
    gun = f"{os.environ['REGISTRY_URL']}/{os.environ['IM_NAME']}"

    key = get_delegation_key(gun=gun)
    if not key:
        logging.error(
            f"Could not find key for {gun} - Please speak to an Administrator"
        )
        sys.exit(1)
    else:
        logging.info("Retrieved key")

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
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        input=key,
        encoding="utf-8",
    )

    if p.returncode != 0:
        logging.error(p.stdout)
        logging.error(p.stderr)
        logging.error(f"Failed to import key for {gun}")
        sys.exit(p.returncode)

    logging.info("Key imported")

    test_auth = os.environ.get("DOCKER_AUTH_CONFIG_TEST").strip()
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
            p = subprocess.run(
                [
                    "skopeo",
                    "inspect",
                    "--authfile",
                    "staging_auth.json",
                    "--raw",
                    f"docker://{staging_image}@{os.environ['IMAGE_PODMAN_SHA']}",
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

            logging.info(f"Pulling {tag}_manifest.json with notary")
            pathlib.Path(f"{tag}_manifest.json").write_text(p.stdout)

            digest = os.environ["IMAGE_PODMAN_SHA"].split(":")[-1]

            manifest = hashlib.sha256(p.stdout.encode())

            if digest == manifest.hexdigest():
                logging.info("Digests match")
            else:
                logging.error(f"Digests do not match {digest}  {manifest.hexdigest()}")
                sys.exit(1)

            logging.info(f"Signing {tag}_manifest.json with notary")

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
                    f"{tag}_manifest.json",
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
