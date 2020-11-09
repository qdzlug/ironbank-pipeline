#!/usr/bin/python3
import gitlab
import sys
import os
import json
import argparse
import logging


gitlab_url = "https://repo1.dsop.io"
dccscr_project_id = 143


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

    parser = argparse.ArgumentParser(description="Lint Whitelist")
    parser.add_argument("--image", help="")
    parser.add_argument("--tag", help="")
    parser.add_argument("--wlbranch", help="")
    args = parser.parse_args()

    im_name = args.image
    wl_branch = args.wlbranch

    im_name = "/".join(im_name.split("/")[1::])

    # get dccscr project object from GitLab
    proj = init(dccscr_project_id)
    
    # Check that image name/tag match provided project values, and all parent images
    get_complete_whitelist_for_image(proj, im_name, wl_branch)

def get_complete_whitelist_for_image(
    proj, im_name, wl_branch, child_image_depth=0
):
    filename = get_whitelist_filename(im_name)
    contents = get_whitelist_file_contents(proj, filename, wl_branch)

    par_image = contents["image_parent_name"]
    
    if (
        contents["approval_status"] != "approved"
        and os.environ.get("CI_COMMIT_BRANCH").lower() == "master"
    ):
        print(f"Error: unapproved image running on master branch", file=sys.stderr)
        sys.exit(1)

    if contents["image_name"] == im_name:
        if len(par_image) > 0:
            get_complete_whitelist_for_image(
                proj,
                par_image,
                wl_branch,
                child_image_depth=child_image_depth + 1,
            )
            # Only output IMAGE_APPROVAL_STATUS on the child image (not for parent images)
            if child_image_depth == 0:
                print(f"IMAGE_APPROVAL_STATUS={contents['approval_status']}")
                print(
                    f"BASE_IMAGE={contents['image_parent_name']}"
                )  # empty string for base image
            else:
                if contents["approval_status"] != "approved":
                    print(
                        f"WARNING: unapproved parent image: {contents['image_name']}",
                        file=sys.stderr,
                    )
        # Output IMAGE_APPROVAL_STATUS for base images like UBI
        elif child_image_depth == 0:
            print(f"IMAGE_APPROVAL_STATUS={contents['approval_status']}")
    else:
        print(
            "Mismatched image name/tag in "
            + filename
            + "\nRetrieved Image Name: "
            + contents["image_name"]
            + ":"
            + contents["image_tag"]
            + "\nSupplied Image Name: "
            + im_name,
            file=sys.stderr,
        )
        sys.exit(1)


def get_whitelist_filename(im_name):
    dccscr_project = im_name.split("/")
    greylist_name = dccscr_project[-1] + ".greylist"
    dccscr_project.append(greylist_name)
    filename = "/".join(dccscr_project)
    return filename


def get_whitelist_file_contents(proj, item_path, item_ref):
    try:
        wl_file = proj.files.get(file_path=item_path, ref=item_ref)
    except:
        print("Error retrieving whitelist file:", sys.exc_info()[1], file=sys.stderr)
        print("Whitelist retrieval attempted: " + item_path, file=sys.stderr)
        sys.exit(1)
    try:
        contents = json.loads(wl_file.decode())
    except ValueError as error:
        print("JSON object issue: %s", file=sys.stderr) % error
        sys.exit(1)
    return contents


def init(pid):
    gl = gitlab.Gitlab(gitlab_url)
    return gl.projects.get(pid)


if __name__ == "__main__":
    main()
