import sys
import os
import asyncio

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from utils import logger  # noqa E402
from project import DsopProject  # noqa E402

log = logger.setup("lint.folder_structure")


async def main():

    log.info("Validating folder structure")
    dsop_project = DsopProject()
    dsop_project.validate_files_exist()
    dsop_project.validate_clamav_whitelist_config()
    dsop_project.validate_trufflehog_config()
    dsop_project.validate_dockerfile()


if __name__ == "__main__":
    asyncio.run(main())
