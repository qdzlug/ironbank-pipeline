#!/usr/bin/env python3

import os
import package_compare
import image_verify
from pathlib import Path

from ironbank.pipeline.utils import logger  # noqa E402

log = logger.setup("lint_jobs")

def main():

    # TODO: Allow fail capability???

    image_verify.verify_manifest()
    image_verify.verify_git_sha()
    image_verify.verify_parent_digest()

    sbom_path = Path(os.environ["ARTIFACT_STORAGE"], "sbom/sbom-json.json")
    access_log_path = Path(os.environ["ARTIFACT_STORAGE"], "build/access_log")

    new_pkgs = package_compare.parse_packages(sbom_path, access_log_path)

    tmp_path = package_compare.download_artifacts()

    old_pkgs = package_compare.parse_packages(Path(tmp_path, 'old_sbom.json'), Path(tmp_path, 'old_access_log'))
    # old_pkgs = package_compare.parse_packages(Path.joinpath(tmp_path, '/sbom-json.json'), Path.joinpath(tmp_path, '/access_log'))

    package_compare.compare(new_pkgs, old_pkgs)


if __name__ == "__main__":
    main()
