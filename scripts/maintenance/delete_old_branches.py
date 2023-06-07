#!/usr/bin/env python3

"""Prunes stale branches
This script will look at all branches for a project and if the mode is delete, remove all branches that haven't been updated in specified number of months.
Expected environment variables:
    - GITLAB_URL: GitLab HTTPS instance URL
    - GITLAB_TOKEN: Access token that provides API write access
    - CI_PROJECT_ID: Project ID the script should operate on
    - STALE_BRANCH_AGE: Number of months to consider a branch as stale. Defaults to 6
    - MODE: dry_run or delete. Defaults to dry_run
"""

import os
from datetime import datetime
from typing import NamedTuple

import gitlab
from dateutil.relativedelta import relativedelta


class ProjectBranch(NamedTuple):
    """Project branch"""

    name: str
    last_updated: str
    state: str


def get_open_merge_requests(project) -> tuple:
    """
    Returns a tuple of the source branch names of open merge requests within a project
    """
    open_merge_requests = project.mergerequests.list(all=True, state="opened")
    open_mr_branches = [x.source_branch for x in open_merge_requests]
    return tuple(open_mr_branches)


def print_branches(
    branch_info: dict[str, list[ProjectBranch]],
    format_val: int,
) -> None:
    """Print branch info for list of ProjectBranches
    Use format_val for padding"""
    padding_len = format_val if format_val < 100 else 100
    for state in branch_info:
        print(f"{state.capitalize()} branch count: {len(branch_info[state])}")
        for branch in (x for x in branch_info[state]):
            print(
                f"""Branch Name:{branch.name:<{padding_len}}\
                    Last Updated: {branch.last_updated}"""
            )
        print()


def delete_stale_branches(
    project,
    branches: dict[str, list[ProjectBranch]],
) -> None:
    """Delete branches in list of ProjectBranches"""
    if not branches["stale"]:
        print("No stale branches to delete")
        return
    for branch in branches["stale"]:
        print(f"Deleting branch: {branch.name}")
        project.branches.delete(branch.name)


def evaluate_branches(
    branches,
    open_mr_branches,
    diff_age,
) -> dict[str, list[ProjectBranch]]:
    """
    Loop through GL project's list of branches to delete any that haven't been updated in the provided amount of time
    Defaults to six (months)
    """
    branch_info: dict[str, list[ProjectBranch]] = {
        "active": [],
        "stale": [],
    }
    diff_age_timestamp = (
        datetime.now() - relativedelta(months=int(diff_age))
    ).timestamp()
    print(f"Searching for branches older than {diff_age} month(s)\n")
    for branch in branches:
        branch_name = branch.name
        committed_date = branch.commit["committed_date"]
        branch_update_age = datetime.strptime(
            committed_date, "%Y-%m-%dT%H:%M:%S.%f%z"
        ).timestamp()
        last_updated = datetime.strftime(
            datetime.utcfromtimestamp(branch_update_age), "%Y-%m-%dT%H:%M:%SZ"
        )
        if (
            diff_age_timestamp > branch_update_age
            and branch_name not in ("master",)
            and branch_name not in open_mr_branches
        ):
            branch_info["stale"].append(
                ProjectBranch(
                    branch_name,
                    last_updated,
                    "stale",
                )
            )
        else:
            branch_info["active"].append(
                ProjectBranch(
                    branch_name,
                    last_updated,
                    "active",
                )
            )
    print(
        f"Total project branches:\t\t{len(branches)}\n"
        f"Total stale branches:\t\t{len(branch_info['stale'])}\n"
    )
    return branch_info


def main() -> None:
    """Main method
    use gitlab-python to retrieve branches and pass to delete function
    """
    url = os.environ["GITLAB_URL"]
    private_token = os.environ["GITLAB_TOKEN"]
    project_id = os.environ["CI_PROJECT_ID"]
    diff_age = os.environ.get("STALE_BRANCH_AGE", 6)

    gl_instance = gitlab.Gitlab(url=url, private_token=private_token)
    gl_instance.auth()

    project = gl_instance.projects.get(project_id)
    branches = project.branches.list(all=True)
    open_mr_branches = get_open_merge_requests(project)

    mode = os.environ.get("MODE", "dry_run")
    print(f"\nMode selected: {mode}")
    branch_data = evaluate_branches(
        branches,
        open_mr_branches,
        diff_age,
    )
    format_val = len(max((x.name for x in branches), key=len))
    print_branches(branch_data, format_val)
    if mode == "delete":
        delete_stale_branches(project, branch_data)


if __name__ == "__main__":
    main()
