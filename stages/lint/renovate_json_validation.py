#!/usr/bin/env python3

from pathlib import Path
import asyncio

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.utils import logger
from ironbank.pipeline.renovate_json import RenovateJson

log = logger.setup(name="lint.metadata")


async def main():
    dsop_project = DsopProject()
    renovate_json = RenovateJson(
        dsop_project.renovate_path,
        Path(
            Path(__file__).parent.parent.parent, "schema/renovate-schema.json"
        ).as_posix(),
        validate=True,
    )
    renovate_json.validate_schema()
    log.info("Renovate.json is validated")


if __name__ == "__main__":
    asyncio.run(main())