#!/usr/bin/env python3

import gitlab
import os
import logging


def getProjects(gl, token, id):
    group = gl.groups.get(id, lazy=True)
    projects = group.projects.list(as_list=False, include_subgroups=True)
    return projects


def check(gl, token, pid, branch_name):
    project = gl.projects.get(pid)
    logging.info(f"Checking project {project.name}")
    __protectBranch(project, branch_name)


def __protectBranch(project, branch_name):
    if branch_name not in (x.name for x in project.protectedbranches.list()):
        logging.warning(f"{project.name} Development branch not protected")
        logging.warning(f"Protecting development branch for {project.name}")
        project.protectedbranches.create(
            {
                "name": branch_name,
                "merge_access_level": gitlab.MAINTAINER_ACCESS,
                "push_access_level": gitlab.NO_ACCESS,
                "unprotect_access_level": gitlab.MAINTAINER_ACCESS,
                "allow_force_push": False,
                "code_owner_approval_required": True,
            }
        )
    else:
        logging.info(f"{project.name} Development branch is already protected")


def main():
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
    gitlab_url = "https://repo1.dso.mil"
    token = os.environ["GL_TOKEN"]
    gl = gitlab.Gitlab(gitlab_url, private_token=token)
    group_id = os.environ["PROJECT_ID"]
    project_lst = getProjects(gl, token, group_id)
    logging.info(f"Number of projects: {len(project_lst)}")
    branch_name = os.getenv("BRANCH_NAME", "development")
    for proj in project_lst:
        check(gl, token, proj.id, branch_name)


if __name__ == "__main__":
    main()
