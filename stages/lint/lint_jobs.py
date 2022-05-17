import asyncio
import hardening_manifest_validation
import folder_structure
import dockerfile_validation
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
            system_exits[se.code].append(func.__module__)

    return _handle_system_exit


async def main():

    await handle_system_exit(folder_structure.main)()
    await handle_system_exit(hardening_manifest_validation.main)()
    await handle_system_exit(dockerfile_validation.main)()
    # await handle_system_exit(container_status_check.main)()
    await handle_system_exit(base_image_validation.main)()
    await handle_system_exit(pipeline_auth_status.main)()

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
