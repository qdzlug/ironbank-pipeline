#!/usr/bin/env python3

import sys
from pathlib import Path

from pipeline.hardening_manifest import HardeningManifest
from pipeline.project import DsopProject
from common.utils import logger

log = logger.setup(name="lint.metadata")


def main():
    """Validate hardening manifest."""
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(
        dsop_project.hardening_manifest_path,
        Path(
            Path(__file__).parent.parent.parent.parent, "schema/hardening_manifest.schema.json"
        ).as_posix(),
        validate=True,
    )
    if hardening_manifest.invalid_labels or hardening_manifest.invalid_maintainers:
        log.error(
            "Please update these labels to appropriately describe your container before rerunning this pipeline"
        )
        sys.exit(1)
    elif hardening_manifest.invalid_image_sources:
        log.warning(
            "Please update these tags to ensure they do not contain registry1.dso.mil"
        )
        sys.exit(100)
    log.info("Hardening manifest is validated")


if __name__ == "__main__":
    main()
