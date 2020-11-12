import logging
import sys
from pathlib import Path

import gitlab
import migration

logging.basicConfig(level=logging.INFO, stream=sys.stdout)

gl = gitlab.Gitlab("https://repo1.dsop.io/", private_token=sys.argv[1])
migration._process_greylist(
    greylist=Path("opensource/pipeline-test-project/kubectl/kubectl.greylist"),
    gl=gl,
    force=True,
    repo1_url="https://repo1.dsop.io/",
    branch="hardening_manifest",
    start_branch="development",
    dccscr_whitelists_branch="pipeline-test-project",
)
