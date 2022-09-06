#!/usr/bin/env python3

"""
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


def evaluate_branches(branches, mode, diff_age) -> None:
    """
    Loop through GL project's list of branches to delete any that haven't been updated in the provided amount of time
    Defaults to six months
    """
    diff_age_timestamp = (
        datetime.now() - relativedelta(months=int(diff_age))
    ).timestamp()
    stale_branch_count = 0
    branch_total = len(branches)
    print(f"Total project branches: {branch_total}")
    for branch in branches:
        branch_name = branch.name
        committed_date = branch.commit["committed_date"]
        branch_update_age = datetime.strptime(
            committed_date, "%Y-%m-%dT%H:%M:%S.%f%z"
        ).timestamp()
        last_updated = datetime.strftime(
            datetime.utcfromtimestamp(branch_update_age), "%Y-%m-%dT%H:%M:%SZ"
        )
        print(f"Searching for branches older than {diff_age} month(s)")
        # if the last update date is more than the defined amount of time, and not in tuple of preserved branches, delete the branch.
        if diff_age_timestamp > branch_update_age and branch_name not in ("master"):
            print(
                f"""Stale branch:\t{branch_name}\n"""
                f"""Last updated:\t{last_updated}\n"""
            )
            stale_branch_count += 1
            if mode == "delete":
                print("Deleting branch")
                branch.delete()
        else:
            print(
                f"""Retaining branch: {branch_name}\n"""
                f"""Last updated:\t{last_updated}\n"""
            )
    print(
        f"""Total stale branches:\t\t{stale_branch_count}\n"""
        f"""Total retained branches:\t{branch_total - stale_branch_count}"""
    )


def main() -> None:
    """
    Main method
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

    mode = os.environ.get("MODE", "dry_run")
    evaluate_branches(branches, mode, diff_age)


if __name__ == "__main__":
    main()
