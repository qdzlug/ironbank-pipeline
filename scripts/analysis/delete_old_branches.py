#!/usr/bin/env python3

import os

# import json
from datetime import datetime
from dateutil.relativedelta import relativedelta
import gitlab


def evaluate_branches(branches, mode="dry_run") -> None:
    """
    Loop through GL project's list of branches to delete any that haven't been updated in 6 months
    """
    six_months_ago = (datetime.now() - relativedelta(months=6)).timestamp()
    for branch in branches:
        branch_name = branch.name
        committed_date = branch.commit["committed_date"]
        branch_update_age = datetime.strptime(
            committed_date, "%Y-%m-%dT%H:%M:%S.%f%z"
        ).timestamp()
        # if the last update date is more than six months ago, and not in tuple of preserved branches, delete the branch.
        if six_months_ago > branch_update_age and branch_name not in ("master"):
            print(
                f"Stale branch:\t{branch_name}\n"
                f"Last updated:\t{datetime.strftime(datetime.utcfromtimestamp(branch_update_age), '%Y-%m-%dT%H:%M:%SZ')}"
            )
            if mode == "dry_run":
                print("Deleting branch")
                branch.delete()
        else:
            print(f"Retaining branch: {branch_name}")


def main() -> None:
    """
    Main method
    use gitlab-python to retrieve branches and pass to delete function
    """
    url = os.environ["GITLAB_URL"]
    private_token = os.environ["GITLAB_TOKEN"]
    project_id = os.environ["CI_PROJECT_ID"]

    gl_instance = gitlab.Gitlab(url=url, private_token=private_token)
    gl_instance.auth()

    project = gl_instance.projects.get(project_id)
    branches = project.branches.list(all=True)

    mode = os.environ.get("MODE", "dry_run")
    evaluate_branches(branches, mode)


if __name__ == "__main__":
    main()
