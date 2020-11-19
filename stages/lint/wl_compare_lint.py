#!/usr/bin/env python3

import os
import sys
import json
import gitlab
import logging
import argparse


REPO1_URL = "https://repo1.dsop.io"
DCCSCR_WHITELIST_PROJECT = "dsop/dccscr-whitelists"


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

    image_name = os.getenv("CI_PROJECT_PATH", default="")
    wl_branch = os.getenv("WL_TARGET_BRANCH", default="master")
    artifacts_path = os.getenv("ARTIFACTS_STORAGE", default="")

    image_name = "/".join(image_name.split("/")[1::])

    # get dccscr project object from GitLab
    proj = init(DCCSCR_WHITELIST_PROJECT)

    # Check that image name/tag match provided project values, and all parent images
    get_complete_whitelist_for_image(proj, image_name, wl_branch)


# TODO: Grabbing these fields from the greylist will be deprecated. Use hardening_manifest.yaml
def get_complete_whitelist_for_image(proj, image_name, wl_branch, child_image_depth=0):

    # Fetch the hardening_manifest.yaml

    filename = get_whitelist_filename(image_name)
    contents = get_whitelist_file_contents(proj, filename, wl_branch)

    par_image = contents["image_parent_name"]

    if (
        contents["approval_status"] != "approved"
        and os.environ.get("CI_COMMIT_BRANCH").lower() == "master"
    ):
        logging.error(f"Unapproved image running on master branch")
        sys.exit(1)

    if contents["image_name"] == image_name:
        if len(par_image) > 0:
            get_complete_whitelist_for_image(
                proj,
                par_image,
                wl_branch,
                child_image_depth=child_image_depth + 1,
            )
            # Only output IMAGE_APPROVAL_STATUS on the child image (not for parent images)
            if child_image_depth == 0:
                logging.info(f"IMAGE_APPROVAL_STATUS={contents['approval_status']}")
                logging.info(
                    f"BASE_IMAGE={contents['image_parent_name']}"
                )  # empty string for base image
            else:
                if contents["approval_status"] != "approved":
                    logging.warning(
                        f"Unapproved parent image: {contents['image_name']}",
                        file=sys.stderr,
                    )
        # Output IMAGE_APPROVAL_STATUS for base images like UBI
        elif child_image_depth == 0:
            logging.info(f"IMAGE_APPROVAL_STATUS={contents['approval_status']}")
    else:
        logging.error(f"Mismatched image name/tag in {filename}")
        logging.error(
            f"Retrieved Image Name: {contents['image_name']}:{contents['image_tag']}"
        )
        logging.error(f"Supplied Image Name: {image_name}")
        sys.exit(1)


def get_whitelist_filename(image_name):
    dccscr_project = image_name.split("/")
    greylist_name = dccscr_project[-1] + ".greylist"
    dccscr_project.append(greylist_name)
    filename = "/".join(dccscr_project)
    return filename


def get_whitelist_file_contents(proj, item_path, item_ref):
    try:
        wl_file = proj.files.get(file_path=item_path, ref=item_ref)
    except:
        logging.error(f"Error retrieving whitelist file: {sys.exc_info()[1]}")
        logging.error(f"Whitelist retrieval attempted: {item_path}")
        sys.exit(1)
    try:
        contents = json.loads(wl_file.decode())
    except ValueError as error:
        logging.error("JSON object issue: {error}")
        sys.exit(1)
    return contents


def init(pid):
    gl = gitlab.Gitlab(REPO1_URL)
    return gl.projects.get(pid)


if __name__ == "__main__":
    sys.exit(main())
