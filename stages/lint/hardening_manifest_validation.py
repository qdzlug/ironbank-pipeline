#!/usr/bin/python3
import sys
from pathlib import Path
import asyncio

from ibmodules.project import DsopProject  # noqa: E402
from ibmodules.utils import logger  # noqa: E402
from ibmodules.hardening_manifest import HardeningManifest  # noqa: E402

log = logger.setup(name="lint.metadata")


async def main():
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(
        dsop_project.hardening_manifest_path,
        Path(
            Path(__file__).parent.parent.parent, "schema/hardening_manifest.schema.json"
        ).as_posix(),
        validate=True,
    )
    hardening_manifest.create_artifacts()
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
    asyncio.run(main())
