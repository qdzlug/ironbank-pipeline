#!/usr/bin/python3
import os
import sys
from pathlib import Path
import asyncio


sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from project import DsopProject  # noqa: E402
from utils import logger  # noqa: E402
from hardening_manifest import HardeningManifest  # noqa: E402

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


if __name__ == "__main__":
    asyncio.run(main())
