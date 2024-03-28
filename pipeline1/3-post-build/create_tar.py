#!/usr/bin/env python3

import json
import os
import subprocess
from pathlib import Path


def main():
    """This function copies images to .tar files via skopeo

    The script requires the following environment variables to be set:
    - 'REGISTRY_PRE_PUBLISH_URL': The URL of the registry where the source image is stored.
    - 'IMAGE_NAME': The name of the image to be copied.
    - 'ARTIFACT_DIR': The artifact directory
    - 'IMAGE_FILE': The base name of the file where the image will be saved (without the '.tar' extension).

    The function uses the Skopeo tool to copy the image from the source to the destination.

    The script does not return anything.
    """

    # copy image to tar for platforms (if digest artifact exists)
    potential_platforms = [
        "amd64",
        "arm64",
    ]

    platforms = [
        {
            "platform": platform,
            "digest": Path(
                f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/digest'
            ).read_text(encoding="utf-8"),
        }
        for platform in potential_platforms
        if os.path.isfile(f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/digest')
    ]

    for platform in platforms:
        # load platform build.json
        with open(
            f"{os.environ['ARTIFACT_STORAGE']}/build/{platform['platform']}/build.json",
            "r",
            encoding="utf-8",
        ) as f:
            build = json.load(f)

        print(f"generating for {platform['platform']}..")
        Path(f"{os.environ['ARTIFACT_DIR']}/{platform['platform']}").mkdir(
            parents=True, exist_ok=True
        )
        subprocess.run(
            [
                "skopeo",
                "copy",
                "--authfile",
                os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"],
                f"docker://{os.environ['REGISTRY_PRE_PUBLISH_URL']}/{build['IMAGE_NAME']}@{platform['digest']}",
                f"docker-archive:{os.environ['ARTIFACT_DIR']}/{platform['platform']}/{os.environ['IMAGE_FILE']}-{platform['platform']}.tar",
            ],
            check=True,
        )


if __name__ == "__main__":
    main()
