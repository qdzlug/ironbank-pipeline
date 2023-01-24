#!/usr/bin/env python3

"""Prunes stale branches
This script will look at all branches for a project and if the mode is delete, remove all branches that haven't been updated in 6 months.
Expected environment variables:
    - GITLAB_URL: GitLab HTTPS instance URL
    - GITLAB_TOKEN: Access token that provides API write access
    - CI_PROJECT_ID: Project ID the script should operate on
    - STALE_BRANCH_AGE: Number of months to consider a branch as stale. Defaults to 6
    - MODE: dry_run or delete. Defaults to dry_run
"""

import os
from datetime import datetime
from dateutil.relativedelta import relativedelta
import gitlab


def get_open_merge_requests(project) -> tuple:
    """
    Returns a tuple of the source branch names of open merge requests within a project
    """
    open_merge_requests = project.mergerequests.list(all=True, state="opened")
    open_mr_branches = [x.source_branch for x in open_merge_requests]
    return tuple(open_mr_branches)


def evaluate_branches(
    branches,
    open_mr_branches,
    mode,
    diff_age,
) -> None:
    """
    Loop through GL project's list of branches to delete any that haven't been updated in the provided amount of time
    Defaults to six (months)
    """
    diff_age_timestamp = (
        datetime.now() - relativedelta(months=int(diff_age))
    ).timestamp()
    stale_branch_count = 0
    branch_total = len(branches)
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
        # if
        #   the last update date is older (less than) than the defined amount of time
        #   not in tuple of preserved branches
        #   not in the tuple of open MR source branch names
        # then delete the branch.
        if (
            diff_age_timestamp > branch_update_age
            and branch_name not in ("master",)
            and branch_name not in open_mr_branches
        ):
            print(
                f"""Stale branch:\t{branch_name}\n"""
                f"""Last updated:\t{last_updated}"""
            )
            stale_branch_count += 1
            if mode == "delete":
                print("Deleting branch")
                branch.delete()
            print()
        else:
            print(
                f"""Retaining branch: {branch_name}\n"""
                f"""Last updated:\t{last_updated}\n"""
            )
    print(
        f"""Total project branches:\t\t{branch_total}\n"""
        f"""Total stale branches:\t\t{stale_branch_count}"""
    )
    if mode == "delete":
        print(f"Total retained branches:\t{branch_total - stale_branch_count}")


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
    evaluate_branches(
        branches,
        open_mr_branches,
        mode,
        diff_age,
    )


if __name__ == "__main__":
    main()
