import asyncio
import metadata
import folder_structure
import registry_validation
import container_status_check
import base_image_validation
import pipeline_auth_status
import sys


system_exits = []


def handle_system_exit(func):
    async def _handle_system_exit(*args, **kwargs):
        try:
            return await func()
        except SystemExit as se:
            system_exits.append(se.code)

    return _handle_system_exit


@handle_system_exit
async def run_metadata():
    await metadata.main()


@handle_system_exit
async def run_registry_validation():
    await registry_validation.main()


@handle_system_exit
async def run_container_status_check():
    await container_status_check.main()


@handle_system_exit
async def run_base_image_validation():
    await base_image_validation.main()


@handle_system_exit
async def run_pipeline_auth_status():
    await pipeline_auth_status.main()


@handle_system_exit
async def run_folder_structure():
    await folder_structure.main()


async def main():

    await run_folder_structure()
    await run_metadata()
    await run_registry_validation()
    await run_container_status_check()
    await run_base_image_validation()
    await run_pipeline_auth_status()

    HARD_FAIL_CODE = 1
    SOFT_FAIL_CODE = 100

    if HARD_FAIL_CODE in system_exits:
        print("Something bad happened")
        sys.exit(HARD_FAIL_CODE)
    elif SOFT_FAIL_CODE in system_exits:
        print("Something less bad happened")
        sys.exit(SOFT_FAIL_CODE)
    else:
        print("All stages successful")


if __name__ == "__main__":
    asyncio.run(main())
