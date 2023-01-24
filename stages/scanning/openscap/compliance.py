#!/usr/bin/python3
import os
import sys
import argparse
import logging


def get_oscap_guide(oscap_version, base_image_type):
    logging.debug("Retrieving Oscap Guide")
    logging.debug(f"Oscap Version: {oscap_version}, Base Image Type: {base_image_type}")

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
        "ol8-container": {
            "profile": "xccdf_org.ssgproject.content_profile_standard",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-ol8-ds.xml",
        },
        "ol7-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-ol7-ds.xml",
        },
        "centos8-container": {
            "profile": "xccdf_org.ssgproject.content_profile_standard",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-centos8-ds.xml",
        },
        "centos7-container": {
            "profile": "xccdf_org.ssgproject.content_profile_standard",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-centos7-ds.xml",
        },
        "debian10-container": {
            "profile": "xccdf_org.ssgproject.content_profile_anssi_np_nt28_high",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-debian10-ds.xml",
        },
        "debian9-container": {
            "profile": "xccdf_org.ssgproject.content_profile_anssi_np_nt28_high",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-debian9-ds.xml",
        },
        "ubuntu1804-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-ubuntu1804-ds.xml",
        },
        "ubuntu2004-container": {
            "profile": "xccdf_org.ssgproject.content_profile_stig",
            "securityGuide": "scap-security-guide-"
            + str(oscap_version)
            + "/ssg-ubuntu2004-ds.xml",
        },
    }
    try:
        oscap_container = oscap_guides[base_image_type]
        print(oscap_container)
    except:  # noqa
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

    parser.add_argument("--oscap-version", dest="version", help="OSCAP Version")
    parser.add_argument("--image-type", dest="type", help="Image type")
    args = parser.parse_args()

    oscap_version = args.version
    base_image_type = args.type

    get_oscap_guide(oscap_version, base_image_type)
