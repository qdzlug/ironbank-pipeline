#!/usr/bin/env python3

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

MR_DESCRIPTION = """Please review the contents of the new `hardening_manifest.yaml` file.

The `image_name`, `image_tag`, `image_parent_name`, `image_parent_tag`, and
`container_owner` fields in the greylist will no longer be used. The greylist
will be updated in a future MR.

`image_name` and `image_tag` have been replaced with the new `name` and `tags`
fields in `hardening_manifest.yaml`. It is now possible for the pipeline to build
different tags on each branch. This allows us to rebuild the `master` branch
while you work on an update with a new tag in `development` and feature
branches.

`image_parent_name` and `image_parent_tag` have been replaced by
`BASE_IMAGE_NAME` and `BASE_IMAGE_TAG` in the `args:` section of
`hardening_manifest.yaml`.

The current `container_owner` has been migrated to the `maintainers:` section
of `hardening_manifest.yaml`. _Please_ add any additional external vendor contacts or
CHT internal members to this list if they maintain this container.

*   [ ] Add any additional internal or external maintainers to the
    `maintainers:` list. At least one `cht_member` should be present and a
    vendor contact if this is a non-opensource image.
*   [ ] Add any required build args to the `args:` list. For example, you may
    want to add a  custom `VERSION` build arg to simplify your `Dockerfile`.
*   [ ] `org.opencontainers.image.title` ...
*   [ ] `org.opencontainers.image.description` ...
*   [ ] `org.opencontainers.image.licenses` Please ensure the license(s) are
    correctly listed. If an open source license is used, please list the
    [SPDX identifier](https://spdx.org/licenses). If this is a commercial image
    you list "ACME Inc. proprietary license" or similar. If the same image
    is available under multiple licenses, you may list "MIT,Apache-2.0" or
    "AGPL-3.0,ACME Inc. proprietary license" as appropriate.
*   [ ] `org.opencontainers.image.url` ...
*   [ ] `org.opencontainers.image.vendor` ...
*   [ ] `org.opencontainers.image.version` ...
*   [ ] `io.dsop.ironbank.image.keywords` ...
*   [ ] `io.dsop.ironbank.image.type` ...
*   [ ] `io.dsop.ironbank.product.name` ...
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
    greylists = _list_greylists(args.repo1_url)
    for greylist in greylists:
        _process_greylist(greylist, gl, **vars(args))


def _process_greylist(
    greylist,
    gl,
    force,
    repo1_url,
    start_branch,
    branch,
    dccscr_whitelists_branch="master",
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
        logger.warning(f"Failed to get branches for {project}")
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
    renovate["regexManagers"] = [
        rm for rm in renovate["regexManagers"] if rm["fileMatch"] != [r"^Jenkinsfile$"]
    ]
    return json.dumps(renovate, indent=2)


def _list_greylists(repo1_url):
    """
    Create the list of greylists from dccscr-whitelists repo
    """
    whitelist_dir = "dccscr-whitelists"
    whitelist_repo_url = f"{repo1_url}/dsop/{whitelist_dir}.git"
    logger.info(f"Cloning {whitelist_repo_url}")

    with tempfile.TemporaryDirectory() as tempdir:
        git.Repo.clone_from(whitelist_repo_url, tempdir)
        for greylist in Path(tempdir).glob("**/*.greylist"):
            yield greylist.relative_to(tempdir)


if __name__ == "__main__":
    main()
