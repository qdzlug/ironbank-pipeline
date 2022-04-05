#!/usr/bin/python3
import os
import sys
import dockerfile

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)


from project import DsopProject  # noqa: E402
from utils import logger  # noqa: E402
from hardening_manifest import HardeningManifest  # noqa: E402

log = logger.setup(name="lint.registry_validation")
import asyncio


async def main():
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)

    log.debug("Checking for valid registry data in resources.")
    invalid_tags = hardening_manifest.reject_invalid_image_sources()
    if invalid_tags:
        log.error(
            "Please update the following tags to ensure they do not contain registry1.dso.mil"
        )
        for tag in invalid_tags:
            log.error(f"The following tag is invalid and must be addressed: {tag}")
        sys.exit(100)
    log.info("Hardening manifest is validated")
    if hardening_manifest.base_image_name or hardening_manifest.base_image_tag:
        parsed_dockerfile = parse_dockerfile("Dockerfile")
        from_statement_list = remove_non_from_statements(parsed_dockerfile)
        invalid_from = validate_final_from(from_statement_list)
        if invalid_from:
            log.error(
                "The final FROM statement in the Dockerfile must be \
                    FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}"
            )
            sys.exit(100)
    log.info("Dockerfile is validated.")


# TODO: Consider moving these to a separate "Dockerfile" module
def remove_non_from_statements(dockerfile_tuple: tuple) -> list:
    from_list = []
    for command in dockerfile_tuple:
        if command.cmd.lower() == "from":
            from_list.append(command)
    return from_list


def validate_final_from(content: list):
    """
    Returns whether the final FROM statement in the Dockerfile is valid, i.e.
    FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}
    """
    if content[-1].value[0] not in (
        "${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}",
        "$BASE_REGISTRY/$BASE_IMAGE:$BASE_TAG",
    ):
        return True
    else:
        return False


def parse_dockerfile(dockerfile_path: str):
    try:
        parsed_file = dockerfile.parse_file(dockerfile_path)
        return parsed_file
    except dockerfile.GoIOError:
        log.error("The Dockerfile could not be opened.")
        sys.exit(1)
    except dockerfile.GoParseError:
        log.error("The Dockerfile is not parseable.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
