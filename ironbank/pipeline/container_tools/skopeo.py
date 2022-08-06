import os
import json
import subprocess

from ironbank.pipeline.utils import logger

log = logger.setup(name="skopeo")


class Skopeo:
    @classmethod
    def inspect(cls, image, docker_config_dir) -> dict:
        cmd = [
            "skopeo",
            "inspect",
            f"docker://{image}",
        ]
        log.info(f"Run inspect cmd: {cmd}")
        # if skopeo inspect fails, because IMAGE value doesn't match a registry1 container name
        #   fail back to using existing functionality

        sha_value = subprocess.run(
            args=cmd,
            stdout=subprocess.PIPE,
            check=True,
            encoding="utf-8",
            env={
                "PATH": os.environ["PATH"],
                "DOCKER_CONFIG": docker_config_dir,
            },
        )
        return json.loads(sha_value.stdout)
