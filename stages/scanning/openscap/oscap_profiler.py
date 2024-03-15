#!/usr/bin/python3

import logging
import os
import sys


def get_oscap_guide(os_type):
    """Returns the SCAP profile to be used on an image."""
    logging.debug(
        f"Determining OSCAP profile and security guide for os_type: {os_type}"
    )

    # this becomes an env file sourced by oscap_scan.sh to determine oscap scanning logic
    oscap_profiles = {
        "alpine317-container": (""),
        "alpine3-container": (""),
        "chainguard-container": (""),
        "debian11-container": (
            "OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_anssi_np_nt28_average\n"
            "OSCAP_DATASTREAM=ssg-debian11-ds.xml\n"
            "OSCAP_SCANNER=debian"
        ),
        "debian12-container": (
            "OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_anssi_np_nt28_average\n"
            "OSCAP_DATASTREAM=ssg-debian12-ds.xml\n"
            "OSCAP_SCANNER=debian"
        ),
        "distroless-container": (""),
        "scratch-container": (""),
        "sle15-bci-container": (
            "OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig\n"
            "OSCAP_DATASTREAM=ssg-sle15-ds.xml\n"
            "OSCAP_OVAL=pub-projects-security-oval-suse.linux.enterprise.15.xml\n"
            "OSCAP_SCANNER=suse"
        ),
        "ubi7-container": (
            "OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig\n"
            "OSCAP_DATASTREAM=ssg-rhel7-ds.xml\n"
            "OSCAP_OVAL=security-data-oval-v2-RHEL7-rhel-7.oval.xml.bz2"
        ),
        "ubi8-container": (
            "OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig\n"
            "OSCAP_DATASTREAM=ssg-rhel8-ds.xml\n"
            "OSCAP_OVAL=security-data-oval-v2-RHEL8-rhel-8.oval.xml.bz2"
        ),
        "ubi9-container": (
            "OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig\n"
            "OSCAP_DATASTREAM=ssg-rhel9-ds.xml\n"
            "OSCAP_OVAL=security-data-oval-v2-RHEL9-rhel-9.oval.xml.bz2"
        ),
        "ubuntu2004-container": (
            "OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig\n"
            "OSCAP_DATASTREAM=ssg-ubuntu2004-ds.xml\n"
            "OSCAP_SCANNER=debian"
        ),
        "ubuntu2204-container": (
            "OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_standard\n"
            "OSCAP_DATASTREAM=ssg-ubuntu2204-ds.xml\n"
            "OSCAP_SCANNER=debian"
        ),
    }
    try:
        oscap_profile = oscap_profiles[os_type]
        print(oscap_profile)
        with open(file="oscap_profile.txt", mode="w", encoding="UTF-8") as f:
            f.write(oscap_profile)
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
