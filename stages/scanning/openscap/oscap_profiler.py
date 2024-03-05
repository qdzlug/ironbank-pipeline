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

    oscap_guides = {}
    oscap_guides = {
        "ubi9-container": {
            "oval": "security-data-oval-v2-RHEL9-rhel-9.oval.xml.bz2",
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel9-ds.xml",
            "scanner": "redhat",
        },
        "ubi9-minimal-container": {
            "oval": "security-data-oval-v2-RHEL9-rhel-9.oval.xml.bz2",
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel9-ds.xml",
            "scanner": "redhat",
        },
        "ubi9-micro-container": {
            "oval": "security-data-oval-v2-RHEL9-rhel-9.oval.xml.bz2",
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel9-ds.xml",
            "scanner": "redhat",
        },
        "ubi8-container": {
            "oval": "security-data-oval-v2-RHEL8-rhel-8.oval.xml.bz2",
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel8-ds.xml",
            "scanner": "redhat",
        },
        "ubi8-minimal-container": {
            "oval": "security-data-oval-v2-RHEL8-rhel-8.oval.xml.bz2",
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel8-ds.xml",
            "scanner": "redhat",
        },
        "ubi8-micro-container": {
            "oval": "security-data-oval-v2-RHEL8-rhel-8.oval.xml.bz2",
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel8-ds.xml",
            "scanner": "redhat",
        },
        "ubi7-container": {
            "oval": "security-data-oval-v2-RHEL7-rhel-7.oval.xml.bz2",
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel7-ds.xml",
            "scanner": "redhat",
        },
        "ubi7-minimal-container": {
            "oval": "security-data-oval-v2-RHEL7-rhel-7.oval.xml.bz2",
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-rhel7-ds.xml",
            "scanner": "redhat",
        },
        "ubuntu2004-container": {
            "oval": "none",
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-ubuntu2004-ds.xml",
            "scanner": "debian",
        },
        "sle15-bci-container": {
            "oval": "pub-projects-security-oval-suse.linux.enterprise.15.xml",
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "ssg-sle15-ds.xml",
            "scanner": "suse",
        },
        "debian11-container": {
            "oval": "none",
            "profile": "xccdf_org.ssgproject.content_profile_anssi_np_nt28_average",
            "securityGuide": "ssg-debian11-ds.xml",
            "scanner": "debian",
        },
        "debian12-container": {
            "oval": "none",
            "profile": "xccdf_org.ssgproject.content_profile_anssi_np_nt28_average",
            "securityGuide": "ssg-debian12-ds.xml",
            "scanner": "debian",
        },
        "alpine317-container": {
            "oval": "none",
            "profile": "none",
            "securityGuide": "none",
            "scanner": "none",
        },
        "alpine3-container": {
            "oval": "none",
            "profile": "none",
            "securityGuide": "none",
            "scanner": "none",
        },
        "chainguard-container": {
            "oval": "none",
            "profile": "none",
            "securityGuide": "none",
            "scanner": "none",
        },
        "distroless-container": {
            "oval": "none",
            "profile": "none",
            "securityGuide": "none",
            "scanner": "none",
        },
        "scratch-container": {
            "oval": "none",
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
