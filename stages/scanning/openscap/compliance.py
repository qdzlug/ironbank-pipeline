#!/usr/bin/python3

import argparse
import logging
import os
import sys


def get_oscap_guide(scap_version, image_type):
    """Returns the SCAP profile to be used on an image."""
    logging.debug("Retrieving Oscap Guide")
    logging.debug("Oscap Version: %s, Base Image Type: %s", scap_version, image_type)

    oscap_guides = {
        "ubi9-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-rhel9-ds.xml",
        },
        "ubi9-minimal-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-rhel9-ds.xml",
        },
        "ubi9-micro-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-rhel9-ds.xml",
        },
        "ubi8-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-rhel8-ds.xml",
        },
        "ubi8-minimal-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-rhel8-ds.xml",
        },
        "ubi8-micro-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-rhel8-ds.xml",
        },
        "ubi7-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-rhel7-ds.xml",
        },
        "ubi7-minimal-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-rhel7-ds.xml",
        },
        "ubuntu2004-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-ubuntu2004-ds.xml",
        },
        "sle15-bci-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-sle15-ds.xml",
        },
        "debian11-container": {
            "profile": "xccdf_org.ssgproject.content_profile_anssi_np_nt28_average",
            "securityGuide": "scap-security-guide-"
            + str(scap_version)
            + "/ssg-debian11-ds.xml",
        },
    }
    try:
        oscap_container = oscap_guides[image_type]
        print(oscap_container)
    except KeyError:
        print("base_image_type does not exist")
        sys.exit(1)


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
    parser = argparse.ArgumentParser(
        description="Retrieve OSCAP security guide for image"
    )

    parser = argparse.ArgumentParser(
        description="Retrieve OSCAP security guide for image"
    )

    parser.add_argument("--oscap-version", dest="version", help="OSCAP Version")
    parser.add_argument("--image-type", dest="type", help="Image type")
    args = parser.parse_args()

    oscap_version = args.version
    base_image_type = args.type

    get_oscap_guide(oscap_version, base_image_type)
