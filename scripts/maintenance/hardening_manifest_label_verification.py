#!/usr/bin/env python3

import gitlab
import yaml
import json
import os
import sys
import logging
from pathlib import Path


def set_log_level():
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


def check_type_label(hm_dict: dict) -> str:
    acceptable_labels = ["opensource", "commercial"]

    if (
        "mil.dso.ironbank.image.type" in hm_dict["labels"]
        and hm_dict["labels"]["mil.dso.ironbank.image.type"].lower()
        not in acceptable_labels
    ):
        return hm_dict["labels"]["mil.dso.ironbank.image.type"]


def check_labels(hm_dict: dict) -> str:
    bad_keys = []
    for k, v in hm_dict["labels"].items():
        if "fixme" in v.lower():
            bad_keys.append(k)
    return bad_keys


def check_maintainers(hm_dict: dict) -> str:
    bad_keys = []
    for d in hm_dict["maintainers"]:
        for k, v in d.items():
            if type(v) != bool and "fixme" in v.lower():
                bad_keys.append(f"{k}: {v}")
    return bad_keys


def main():

    set_log_level()

    GL_URL = os.environ["GITLAB_URL"]
    GL_TOKEN = os.environ["GITLAB_TOKEN"]
    try:
        gl = gitlab.Gitlab(GL_URL, private_token=GL_TOKEN)
    except Exception as e:
        logging.error(f"Failed to get Gitlab object: {e}")
        sys.exit(1)

    dsop_group = gl.groups.get("dsop")

    dsop_group_projects = dsop_group.projects.list(all=True, include_subgroups=True)

    dsop_projects = []

    print(f"Group length: {len(dsop_group_projects)}")

    for project in dsop_group_projects:
        dsop_projects.append(gl.projects.get(project.id))
    bad_hm = []

    for project in dsop_projects:
        try:
            f = (
                project.files.get(file_path="hardening_manifest.yaml", ref="master")
                .decode()
                .decode("utf-8")
            )
            hm_dict = yaml.safe_load(f)
            checked_type_labels = check_type_label(hm_dict)
            checked_labels = check_labels(hm_dict)
            checked_maintainers = check_maintainers(hm_dict)
            logging.info(f"Project ID: {project.id}")
            if checked_type_labels or checked_labels or checked_maintainers:
                bad_hm.append(
                    {
                        "image_url": project.web_url,
                        "project_id": project.id,
                        "bad_type_labels": checked_type_labels,
                        "bad_labels": checked_labels,
                        "bad_maintainers": checked_maintainers,
                    }
                )
        except yaml.YAMLError as e:
            logging.error(e)
            # sys.exit(1)
        except gitlab.exceptions.GitlabHttpError as e:
            logging.warning(e)
        except gitlab.exceptions.GitlabGetError as e:
            logging.warning(e)
        except Exception as e:
            print(f"Project URL: {project.web_url}")
            logging.error(f"Generic exception {e}")
            # sys.exit(1)

    with Path("failures.json").open("w") as f:
        json.dump(bad_hm, f)


if __name__ == "__main__":
    main()
