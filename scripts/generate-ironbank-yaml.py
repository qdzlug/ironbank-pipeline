#!/usr/bin/env python3

import sys
import argparse


def fetch_greylist(url):
    return f"{url}: greylist"


def fetch_download(url):
    return f"{url}: download"


def fetch_jenkinsfile(url):
    return f"{url}: jenkinsfile"


def build_ironbank_yaml(greylist, download, jenkinsfile=None):
    print(greylist)
    print(download)
    print(jenkinsfile)


def main():

    parser = argparse.ArgumentParser(description="IronBank Yaml Generator")
    parser.add_argument(
        "--project",
        default="",
        type=str,
        help="Project to generate ironbank.yaml for",
    )

    parser.add_argument(
        "--repo1-url",
        default="https://repo1.dsop.io",
        type=str,
        help="Repo1 URL",
    )
    args = parser.parse_args()
    # End arguments

    url = f"{args.repo1_url}/dsop/{args.project}"

    greylist = fetch_greylist(url)
    download = fetch_download(url)
    jenkinsfile = fetch_jenkinsfile(url)
    build_ironbank_yaml(greylist, download, jenkinsfile)

    return 0


if __name__ == "__main__":
    sys.exit(main())
