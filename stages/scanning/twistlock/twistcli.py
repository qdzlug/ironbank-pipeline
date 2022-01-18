import os
import sys
import json
import logging
import subprocess
import requests
import argparse
from requests.auth import HTTPBasicAuth


# class Twist:
#     """
#     Class to use twistcli to scan images and parse findings

#     """

#     def __init__(self, user: str, password: str, console_url: str, image: str):
#         self.base_url  = console_url
#         self.username  = user
#         self.password  = password
#         self.image_tag = image


def get_console_version(base_url, username, password, version_file) -> str:
    logging.info(f"Fetching Twistlock Console version from {base_url}/v1/version")
    r = requests.get(f"{base_url}/v1/version", auth=HTTPBasicAuth(username, password))

    version = ""

    if r.status_code != 200:
        logging.error(
            f"Unable to retrieve Console version, query responded with HTTP code {r.status_code}"
        )
        sys.exit(1)
    else:
        version = r.text
        logging.info(f"Twistlock Console version {version}")
        with open(version_file, "w") as f:
            f.write(version)
    print("\n")

    return version


def scan_image(base_url, username, password, filename, image_name) -> None:
    cmd = [
        "twistcli",
        "images",
        "scan",
        "--address",
        base_url,
        "--user",
        username,
        "--password",
        password,
        "--containerized",
        "--podman-path=podman",
        "--custom-labels",
        image_name,
    ]

    try:
        logging.info(f"{' '.join(cmd[0:5])} {' '.join(cmd[9:])}")
        findings = subprocess.run(
            cmd,
            encoding="utf-8",
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        logging.info("Scan successful")
        with open(filename, mode="w") as f:
            json.dump(findings.stdout, f, indent=4)
    except subprocess.SubprocessError:
        logging.error("Could not generate scan report")
        sys.exit(1)
    except Exception:
        logging.exception("Unknown error when ")


# def twistlock_scan(
#     name,
#     digest,
#     username,
#     password,
#     version_file,
#     filename,
#     twistlock_api,
#     registry,
# ):
#     twist = Twist(
#         registry=registry, username=username, password=password, url=twistlock_api
#     )

#     # Capture the console version
#     twist.print_version(version_file)

#     # Scan the image
#     logging.info(f"Starting twistcli scan for {name}@{digest}")
#     twist.add_image(name, digest)

#     twist.scan_image(filename, f"{name}@{digest}")


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
        description="DCCSCR processing of CVE reports from various sources"
    )

    parser.add_argument("--image_name", help="Name of the image using sha256 digest")
    parser.add_argument("--username", help="Twistlock API Username")
    parser.add_argument("--password", help="Twistlock API Password")
    parser.add_argument("--version_file", help="Output filename for twistlock version")
    parser.add_argument("--report_file", help="Output filename for cve report")
    parser.add_argument("--api_url", help="Twistlock API URL")

    args = parser.parse_args()

    logging.info(args)

    version = get_console_version(
        args.api_url, args.username, args.password, args.version_file
    )

    print(f"Twistlock Console version: {version}")

    scan_image(
        args.api_url, args.username, args.password, args.report_file, args.image_name
    )

    # twistlock_scan(
    #     registry=args.registry_url,
    #     twistlock_api=args.api_url,
    #     name=args.name,
    #     digest=args.digest,
    #     username=args.username,
    #     password=args.password,
    #     version_file=args.version_file,
    #     filename=args.report_filename,
    # )
