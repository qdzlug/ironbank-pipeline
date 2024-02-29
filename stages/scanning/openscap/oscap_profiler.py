#!/usr/bin/python3

import json
import logging
import os
import sys


def get_oscap_guide(os_type):
    """Returns the SCAP profile to be used on an image."""
    logging.debug(
        f"Determining OSCAP profile and security guide for os_type: {os_type}"
    )

    oscap_guides = {
        "ubi9-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel9-ds.xml",
            "scanner": "redhat",
        },
        "ubi9-minimal-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel9-ds.xml",
            "scanner": "redhat",
        },
        "ubi9-micro-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel9-ds.xml",
            "scanner": "redhat",
        },
        "ubi8-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel8-ds.xml",
            "scanner": "redhat",
        },
        "ubi8-minimal-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel8-ds.xml",
            "scanner": "redhat",
        },
        "ubi8-micro-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel8-ds.xml",
            "scanner": "redhat",
        },
        "ubi7-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel7-ds.xml",
            "scanner": "redhat",
        },
        "ubi7-minimal-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel7-ds.xml",
            "scanner": "redhat",
        },
        "ubuntu2004-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-ubuntu2004-ds.xml",
            "scanner": "debian",
        },
        "sle15-bci-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-sle15-ds.xml",
            "scanner": "suse",
        },
        "debian11-container": {
            "profile": "xccdf_org.ssgproject.content_profile_anssi_np_nt28_average",
            "securityGuide": "ssg-debian11-ds.xml",
            "scanner": "debian",
        },
        "debian12-container": {
            "profile": "xccdf_org.ssgproject.content_profile_anssi_np_nt28_average",
            "securityGuide": "ssg-debian12-ds.xml",
            "scanner": "debian",
        },
        "alpine317-container": {
            "profile": "none",
            "securityGuide": "none",
            "scanner": "none",
        },
        "alpine3-container": {
            "profile": "none",
            "securityGuide": "none",
            "scanner": "none",
        },
        "chainguard-container": {
            "profile": "none",
            "securityGuide": "none",
            "scanner": "none",
        },
        "distroless-container": {
            "profile": "none",
            "securityGuide": "none",
            "scanner": "none",
        },
        "scratch-container": {
            "profile": "none",
            "securityGuide": "none",
            "scanner": "none",
        },
    }
    try:
        oscap_guide = oscap_guides[os_type]
        print(json.dumps(oscap_guide))
    except KeyError:
        print(f"OS_TYPE {os_type} not found!")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.error(f"supply an OS_TYPE, try: {sys.argv[0]} debian12-container")
        sys.exit(1)

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

    get_oscap_guide(sys.argv[1])
