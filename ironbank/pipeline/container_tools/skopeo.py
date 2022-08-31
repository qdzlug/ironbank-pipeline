import os
import json
import subprocess

from ironbank.pipeline.utils import logger
from ironbank.pipeline.image import Image
from dataclasses import dataclass
from abc import ABC

log = logger.setup(name="skopeo")


@dataclass
class ContainerTool(ABC):
    authfile: str = None
    docker_config_dir: str = None
    src_authfile: str = None
    dest_authfile: str = None


@dataclass
class Skopeo(ContainerTool):
    def inspect(self, image: Image) -> dict:
        # use tag by default, else use digest
        cmd = [
            "skopeo",
            "inspect",
            f"docker://{image.tag_str()}"
            if image.tag
            else f"docker://{image.digest_str()}",
        ]
        log.info(f"Run inspect cmd: {cmd}")
        # if skopeo inspect fails, because IMAGE value doesn't match a registry1 container name
        #   fail back to using existing functionality

        inspect_result = subprocess.run(
            args=cmd,
            stdout=subprocess.PIPE,
            check=True,
            encoding="utf-8",
            env={
                "PATH": os.environ["PATH"],
                "DOCKER_CONFIG": self.docker_config_dir or "",
            },
        )
        return json.loads(inspect_result.stdout)
