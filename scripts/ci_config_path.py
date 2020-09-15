#!/usr/bin/env python3

# Usage:
#   PRIVATE_TOKEN=qwertyuiopasdfghjklz ./gitlab-project-settings.py dsop/opensource/pipeline-test-project
#   PRIVATE_TOKEN=qwertyuiopasdfghjklz ./gitlab-project-settings.py dsop

import gitlab
import os
import sys
import logging

CI_CONFIG_PATH = "templates/default.yaml@ironbank-tools/ironbank-pipeline"

logging.basicConfig(level=logging.INFO)

project_name = sys.argv[1]
gl = gitlab.Gitlab("http://repo1.dsop.io/", private_token=os.environ["PRIVATE_TOKEN"])

logging.info(f"Fetching group: {project_name}")
group = gl.groups.get(project_name)
for group_project in group.projects.list(all=True, per_page=1000, include_subgroups=True):
    logging.info(f"Updating project: {group_project.name_with_namespace}")
    project = gl.projects.get(group_project.id)

    # Update the Custom CI configuration path of the project
    # https://docs.gitlab.com/ee/ci/pipelines/settings.html#custom-ci-configuration-path
    project.ci_config_path = CI_CONFIG_PATH
    project.save()
