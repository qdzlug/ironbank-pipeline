#!/usr/bin/env python3

from base64 import b64decode
import logging
import os
import pathlib
import subprocess
import sys

import yaml


def _load_local_hardening_manifest():
    """
    Load up the hardening_manifest.yaml file as a dictionary. Search for the file in
    the immediate repo first, if that is not found then search for the generated file.

    If neither are found then return None and let the calling function handle the error.

    """
    path = pathlib.Path("hardening_manifest.yaml")

    if path.is_file():
        logging.debug(f"Using {path}")
        with path.open("r") as f:
            return yaml.safe_load(f)
    else:
        logging.debug(f"Couldn't find {path}")
    return None


def skopeo_inspect_base_image(base_image, base_tag):
    #
    # Use the local hardening manifest to get the first parent. From here *only* the
    # the master branch should be used for the ancestry.
    #

    if os.environ.get("STAGING_BASE_IMAGE"):
        auth_file = "staging_pull_auth.json"
        # Grab prod pull docker auth
        pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_STAGING"]).decode("UTF-8")
        pathlib.Path(auth_file).write_text(pull_auth)
        registry = "ironbank-staging"
    else:
        auth_file = "prod_pull_auth.json"
        # Grab staging docker auth
        pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_PULL"]).decode("UTF-8")
        pathlib.Path(auth_file).write_text(pull_auth)
        registry = "ironbank"

    # get parent cves from VAT
    cmd = [
        "skopeo",
        "inspect",
        "--authfile",
        auth_file,
        f"docker://registry1.dso.mil/{registry}/{base_image}:{base_tag}",
    ]
    logging.info(" ".join(cmd))
    # if skopeo inspect fails, because BASE_IMAGE value doesn't match a registry1 container name
    #   fail back to using existing functionality
    try:
        subprocess.run(
            args=cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logging.error(
            "Failed to inspect BASE_IMAGE:BASE_TAG provided in hardening_manifest. Please validate this image exists in the registry1.dso.mil/ironbank project."
        )
        logging.error(
            f"Failed 'skopeo inspect' of image: registry1.dso.mil/{registry}/{base_image}:{base_tag} "
        )
        logging.error(f"Return code: {e.returncode}")
        sys.exit(1)
    except Exception:
        logging.exception("Unknown failure when attemping to inspect BASE_IMAGE")
        sys.exit(1)


def main():
    #
    # Hardening manifest is expected for all of the current repos that are being processed.
    # At the very least the hardening_manifest.yaml should be generated if it has not been
    # merged in yet.
    #

    hardening_manifest = _load_local_hardening_manifest()
    if not hardening_manifest:
        logging.error("Your project must contain a hardening_manifest.yaml")
        sys.exit(1)
    else:
        base_image = hardening_manifest["args"]["BASE_IMAGE"]
        base_tag = hardening_manifest["args"]["BASE_TAG"]
        with open("variables.env", "w") as f:
            f.write(f"BASE_IMAGE={base_image}\n")
            f.write(f"BASE_TAG={base_tag}")
            logging.debug(f"BASE_IMAGE={base_image}\nBASE_TAG={base_tag}")
    if base_image:
        skopeo_inspect_base_image(base_image, base_tag)


if __name__ == "__main__":
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
    main()
