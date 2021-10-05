#!/usr/bin/env python3

##
#
#   Utilizes the following environment variable
#   - LOGLEVEL
#   - ARTIFACT_STORAGE
#   - WL_TARGET_BRANCH
#   - DISTROLESS
#
##

import argparse
from base64 import b64decode
import json
import logging
import os
import pathlib
import subprocess
import sys

import gitlab
import yaml
from collections import namedtuple
from scanners import oscap
from scanners import anchore
from scanners import twistlock


def _load_local_hardening_manifest():
    """
    Load up the hardening_manifest.yaml file as a dictionary. Search for the file in
    the immediate repo first, if that is not found then search for the generated file.

    If neither are found then return None and let the calling function handle the error.

    """
    artifacts_path = os.environ["ARTIFACT_STORAGE"]
    paths = [
        pathlib.Path("hardening_manifest.yaml"),
        # Check for the generated hardening manifest. This method will be deprecated.
        pathlib.Path(artifacts_path, "preflight", "hardening_manifest.yaml"),
    ]

    for path in paths:
        logging.debug(f"Looking for {path}")
        if path.is_file():
            logging.debug(f"Using {path}")
            with path.open("r") as f:
                return yaml.safe_load(f)
        else:
            logging.debug(f"Couldn't find {path}")
    return None


def skopeo_inspect_base_image(hardening_manifest):
    #
    # Use the local hardening manifest to get the first parent. From here *only* the
    # the master branch should be used for the ancestry.
    #
    base_image = hardening_manifest["args"]["BASE_IMAGE"]
    base_tag = hardening_manifest["args"]["BASE_TAG"]

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
    while base_image:
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
            response = subprocess.run(
                args=cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logging.error(
                f"Failed 'skopeo inspect' of image: registry1.dso.mil/{registry}/{base_image}:{base_tag} "
            )
            logging.error(f"Return code: {e.returncode}")
            sys.exit(1)
        except Exception:
            logging.exception("Unknown failure when attemping to inspect BASE_IMAGE")
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

    # Arguments
    parser = argparse.ArgumentParser(description="Run pipelines arguments")
    parser.add_argument(
        "--lint",
        action="store_true",
        help="Lint flag to run the setup but not the business logic",
    )
    args = parser.parse_args()
    # End arguments

    #
    # Hardening manifest is expected for all of the current repos that are being processed.
    # At the very least the hardening_manifest.yaml should be generated if it has not been
    # merged in yet.
    #

    hardening_manifest = _load_local_hardening_manifest()
    if hardening_manifest is None:
        logging.error("Your project must contain a hardening_manifest.yaml")
        sys.exit(1)

    skopeo_inspect_base_image(hardening_manifest)


if __name__ == "__main__":
    main()
