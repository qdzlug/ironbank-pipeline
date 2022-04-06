import asyncio
import metadata
import folder_structure
import registry_validation
import container_status_check
import base_image_validation
import pipeline_auth_status
import sys


system_exits = {}


def handle_system_exit(func):
    async def _handle_system_exit(*args, **kwargs):
        try:
            return await func()
        except SystemExit as se:
            system_exits[se.code] = (
                system_exits[se.code] if system_exits.get(se.code) else []
            )
            system_exits[se.code].append(func.__name__)

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

    for error_code, stages in system_exits.items():
        print(f"The following stages returned error code: {error_code}")
        for stage in stages:
            print(f"\t- {stage}")

    if HARD_FAIL_CODE in system_exits.keys():
        print("Failing pipeline")
        sys.exit(HARD_FAIL_CODE)
    elif SOFT_FAIL_CODE in system_exits.keys():
        print("Failing pipeline")
        sys.exit(SOFT_FAIL_CODE)
    else:
        print("All stages successful")


if __name__ == "__main__":
    asyncio.run(main())
