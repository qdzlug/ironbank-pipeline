#!/usr/bin/python3

import sys
import argparse

from ironbank.pipeline.utils import logger

log = logger.setup("Compliance Profiles")


def get_oscap_guide(oscap_version, base_image_type):
    """Returns the SCAP profile to be used on an image"""
    log.debug("Retrieving Oscap Guide")
    log.debug("Oscap Version: %s, Base Image Type: %s", oscap_version, base_image_type)

    oscap_guides = {
        "ubi9-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-rhel9-ds.xml",
        },
        "ubi9-minimal-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-rhel9-ds.xml",
        },
        "ubi9-micro-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-rhel9-ds.xml",
        },
        "ubi8-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-rhel8-ds.xml",
        },
        "ubi7-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-rhel7-ds.xml",
        },
        "ubi8-minimal-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-rhel8-ds.xml",
        },
        "ubi7-minimal-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-rhel7-ds.xml",
        },
        "ubi8-micro-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-rhel8-ds.xml",
        },
        "ubuntu2004-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-ubuntu2004-ds.xml",
        },
        "sle15-bci-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-sle15-ds.xml",
        },
    }
    try:
        oscap_container = oscap_guides[base_image_type]
        log.info(oscap_container)
    except KeyError:
        log.error("base_image_type does not exist")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Retrieve OSCAP security guide for image"
    )

    parser.add_argument("--oscap-version", dest="version", help="OSCAP Version")
    parser.add_argument("--image-type", dest="type", help="Image type")
    args = parser.parse_args()

    oscap_version = args.version
    base_image_type = args.type

    get_oscap_guide(oscap_version, base_image_type)
