#!/usr/bin/env python3

import sys
import argparse
import requests


def fetch_file(url, file, branch):

    dl_url = f"{url}/-/raw/{branch}/{file}"

    print(dl_url)

    try:
        r = requests.get(url=dl_url)
    except requests.exceptions.RequestException as e:
        print(e)
        raise requests.exceptions.RequestException

    if r.status_code == 200:
        return r.text


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
        "--token",
        default="",
        type=str,
        help="Repo1 Token",
    )

    parser.add_argument(
        "--repo1-url",
        default="https://repo1.dsop.io",
        type=str,
        help="Repo1 URL",
    )
    args = parser.parse_args()
    # End arguments

    project_url = f"{args.repo1_url}/dsop/{args.project}"
    greylist_url = f"{args.repo1_url}/dsop/dccscr-whitelists"

    try:
        greylist = fetch_file(
            url=greylist_url,
            file=f"{args.project}/enterprise.greylist",
            branch="master",
        )
        download = fetch_file(
            url=project_url, file="download.json", branch="development"
        )
        if download is None:
            download = fetch_file(
                url=project_url, file="download.yaml", branch="development"
            )
        jenkinsfile = fetch_file(
            url=project_url, file="Jenkinsfile", branch="development"
        )
    except requests.exceptions.RequestException:
        raise requests.exceptions.RequestException

    build_ironbank_yaml(greylist, download, jenkinsfile)

    return 0


if __name__ == "__main__":
    sys.exit(main())
