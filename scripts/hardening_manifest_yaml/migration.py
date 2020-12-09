#!/usr/bin/env python3

""""
Submit an MR to all dsop repositories to migrate them to hardening_manifest.yaml

Usage:
    Testing:
        python ./scripts/hardening_manifest_yaml/migration.py --repo1-token="your-personal-access-token" --dccscr-whitelists-branch=pipeline-test-project --dccscr-whitelists-path=opensource/pipeline-test-project
    Run the full migration:
        python ./scripts/hardening_manifest_yaml/migration.py --repo1-token="ironbank-bot-personal-access-token" --force
"""

import argparse
import io
import json
import logging
import sys
import tempfile
from pathlib import Path

import git
import gitlab
from dockerfile_parse import DockerfileParser

import generate

MR_DESCRIPTION = """
Please review the contents of the new `hardening_manifest.yaml` file.

The `image_name`, `image_tag`, `image_parent_name`, `image_parent_tag`, and
`container_owner` fields in the greylist will no longer be used. The greylist
will be updated in a future MR.

`image_name` and `image_tag` have been replaced with the new `name` and `tags`
fields in `hardening_manifest.yaml`.

:tada: It is now possible for the pipeline to build different tags on each branch.
This allows us to rebuild the `master` branch while you work on an update with a
new tag in `development` or feature branches.

`image_parent_name` and `image_parent_tag` have been replaced by
`BASE_IMAGE` and `BASE_TAG` in the `args:` section of
`hardening_manifest.yaml`. You can also add custom args like `MY_VERSION`
that referenced as `ARG MY_VERSION` in your `Dockerfile`.

Please review the following:

* Tags
   * The most specific tag should be at the top of the `tags` list.  For example, `v1.2.3` comes before `v1.2`.
   * The first tag will be shown on https://ironbank.dsop.io
   * Additional tags may be added if desired and will be published to https://registry1.dsop.io
* Labels
   * [ ] `org.opencontainers.image.title`: **Required.** Human-readable title of the image
   * [ ] `org.opencontainers.image.description`: **Required.** Human-readable description of the software packaged in the image
   * [ ] `org.opencontainers.image.licenses`: **Required.** License(s) under which contained software is distributed. Please use the [SPDX identfier](https://spdx.org/licenses/) if using a standard open source license.
   * [ ] `org.opencontainers.image.url`: URL to find more information on the image
   * [ ] `org.opencontainers.image.vendor`: **Required.** Name of the distributing entity, organization or individual
   * [ ] `org.opencontainers.image.version`: **Required.** Human readable version of the image. This is typically identical to the first tag.
   * [ ] `mil.dso.ironbank.image.keywords`: Keywords to help with search (ex. "cicd,gitops,golang")
   * [ ] `mil.dso.ironbank.image.type`: This value can be "opensource" or "commercial"
   * [ ] `mil.dso.ironbank.product.name`: Product the image belongs to for grouping multiple images. If you have multiple images that you would like grouped together on https://ironbank.dsop.io, use the same product name on them all.
* Maintainers
  * [ ] _Please_ add any additional external vendor contacts or CHT internal members to this list if they maintain this container.
  * Add any Iron Bank team members who maintain this container with `cht_member: true` set
  * The current `container_owner` has already been added to the `maintainers:` section
of `hardening_manifest.yaml`.
  * Can include POCs in technical and/or support roles. For containers which require licenses or subscriptions, it is encouraged to include a point of contact who can provide assistance in this regard, in addition to a technical POC.

The pipeline will not run successfully for this MR until all of the required fields are added.
"""

logger = logging.getLogger("hardening_manifest_yaml.migration")


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument(
        "--force",
        default=False,
        type=bool,
        help="Testing flag to dry run the script",
    )
    parser.add_argument(
        "--dccscr-whitelists-branch",
        default="master",
        help="Testing flag to use a different branch of dccscr-whitelists",
    )
    parser.add_argument(
        "--dccscr-whitelists-path",
        default="",
        help="Testing flag to use a subdirectory of dccscr-whitelists",
    )
    parser.add_argument(
        "--repo1-token",
        required=True,
        help="Personal access token for accessing gitlab",
    )
    parser.add_argument(
        "--repo1-url",
        default="https://repo1.dsop.io/",
        help="URL for Repo1",
    )
    parser.add_argument(
        "--start-branch",
        default="development",
        help="Branch to make MRs againt",
    )
    parser.add_argument(
        "--branch",
        default="hardening_manifest",
        help="New branch name for MR",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Log level",
        choices=("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"),
    )
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level, stream=sys.stdout)

    if not args.force:
        logger.warning(
            "Running in dry run mode, pass --force to this script to create MRs"
        )

    gl = gitlab.Gitlab(args.repo1_url, private_token=args.repo1_token)
    greylists = _list_greylists(
        args.repo1_url, args.dccscr_whitelists_branch, args.dccscr_whitelists_path
    )
    for greylist in greylists:
        _process_greylist(greylist, gl, **vars(args))


def _process_greylist(
    greylist,
    gl,
    force,
    repo1_url,
    start_branch,
    branch,
    dccscr_whitelists_branch,
    **kwargs,
):
    # Path to the greylist in the repo
    greylist_path = greylist.as_posix()
    # Everything but the final *.greylist filename is the project name
    project = "dsop/" + "/".join(greylist.parts[:-1])

    logger.info(f"Processing {project}")

    try:
        gl_project = gl.projects.get(project, lazy=True)
        branches = [b.name for b in gl_project.branches.list()]
    except gitlab.exceptions.GitlabListError:
        # Old greylists like dsop/opensource/foo/1.2.3/foo-1.2.3.greylist will result in an error that can be ignored
        logger.info(f"Failed to get branches for {project}")
        return

    if start_branch not in branches:
        logger.error(f"{project} does not have {start_branch} branch")
        return

    if branch in branches:
        logger.info(f"{project} already has {branch} branch, skipping")
        return

    try:
        tree = [f["path"] for f in gl_project.repository_tree(ref=start_branch)]
    except gitlab.exceptions.GitlabError:
        logger.exception(f"Failed to list repository tree for {project}")
        return

    if "hardening_manifest.yaml" in tree:
        logger.info(f"{project} already has hardening_manifest.yaml, skipping")
        return

    try:
        yaml = generate.generate(
            greylist_path=greylist_path,
            repo1_url=repo1_url,
            dccscr_whitelists_branch=dccscr_whitelists_branch,
        )
    except generate.FileNotFound as e:
        logger.error(f"File not found in {project}: {e}")
        return
    except Exception:
        logger.exception("Failed to generate hardening_manifest.yaml")
        return

    actions = [
        {
            "action": "create",
            "file_path": "hardening_manifest.yaml",
            "content": yaml,
        },
    ]

    for path in ("Jenkinsfile", "download.json", "download.yaml"):
        if path in tree:
            actions.append(
                {
                    "action": "delete",
                    "file_path": path,
                }
            )

    if "Dockerfile" in tree:
        try:
            dockerfile = _process_dockerfile(gl_project, start_branch)
        except Exception:
            logger.exception(f"Failed to process Dockerfile in {project}")
            return

        actions.append(
            {
                "action": "update",
                "file_path": "Dockerfile",
                "content": dockerfile,
            }
        )

    if "renovate.json" in tree:
        try:
            renovate = _process_renovate(gl_project, start_branch)
        except Exception:
            logger.exception(f"Failed to process renovate.json in {project}")
            return

        if renovate:
            actions.append(
                {
                    "action": "update",
                    "file_path": "renovate.json",
                    "content": renovate,
                }
            )

    # Stop processing at this point for a dry run
    if not force:
        return

    try:
        # https://docs.gitlab.com/ee/api/commits.html#create-a-commit-with-multiple-files-and-actions
        gl_project.commits.create(
            {
                "commit_message": "Migrate to hardening_manifest.yaml",
                "branch": branch,
                "start_branch": start_branch,
                "actions": actions,
            }
        )
    except gitlab.exceptions.GitlabError:
        logger.exception(f"Failed to create commit on {project}")
        return

    try:
        # https://docs.gitlab.com/ee/api/merge_requests.html#create-mr
        gl_project.mergerequests.create(
            {
                "source_branch": branch,
                "target_branch": start_branch,
                "title": "Migrate to hardening_manifest.yaml",
                "labels": ["hardening_manifest.yaml migration"],
                "description": MR_DESCRIPTION,
            }
        )
    except gitlab.exceptions.GitlabError:
        logger.exception(f"Failed to make MR on {project}")
        return

    logger.info(f"MR successfully created on {project}")


def _process_dockerfile(gl_project, ref):
    dockerfile = io.BytesIO(gl_project.files.get("Dockerfile", ref).decode())
    dfp = DockerfileParser(fileobj=dockerfile)
    dfp.labels = {}
    return dfp.content


def _process_renovate(gl_project, ref):
    renovate = json.loads(gl_project.files.get("renovate.json", ref).decode())

    if "regexManagers" not in renovate:
        return None

    jenkinsManagers = []
    for m in renovate["regexManagers"]:
        if m["fileMatch"] == [r"^Jenkinsfile$"]:
            renovate["regexManagers"].remove(m)
            jenkinsManagers.append(m)

    if not jenkinsManagers:
        return None

    if len(jenkinsManagers) > 1:
        logger.warning("Multiple regexManagers found in renovate.json for Jenkinsfile")

    # Hopefully there aren't multiple regexManagers applied to Jenkinsfiles
    assert jenkinsManagers[0]["matchStrings"] == [r'version:\s+"(?<currentValue>.*?)"']

    renovate["regexManagers"].append(
        {
            **jenkinsManagers[0],
            "fileMatch": [r"^hardening_manifest.yaml$"],
            "matchStrings": [
                r'org\.opencontainers\.image\.version:\s+"(?<currentValue>.+?)"'
            ],
        }
    )
    renovate["regexManagers"].append(
        {
            **jenkinsManagers[0],
            "fileMatch": [r"^hardening_manifest.yaml$"],
            "matchStrings": [r'tags:\s+-\s+"(?<currentValue>.+?)"'],
        }
    )
    return json.dumps(renovate, indent=2)


def _list_greylists(repo1_url, dccscr_whitelists_branch, dccscr_whitelists_path):
    """
    Create the list of greylists from dccscr-whitelists repo
    """
    whitelist_dir = "dccscr-whitelists"
    whitelist_repo_url = f"{repo1_url}/dsop/{whitelist_dir}.git"
    logger.info(f"Cloning {dccscr_whitelists_branch} branch of {whitelist_repo_url}")

    with tempfile.TemporaryDirectory() as tempdir:
        git.Repo.clone_from(
            whitelist_repo_url, tempdir, branch=dccscr_whitelists_branch
        )
        for greylist in Path(tempdir, dccscr_whitelists_path).glob("**/*.greylist"):
            yield greylist.relative_to(tempdir)


if __name__ == "__main__":
    main()
