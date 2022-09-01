import os
import json
import subprocess
from pathlib import Path

from ironbank.pipeline.utils import logger
from ironbank.pipeline.image import Image
from dataclasses import dataclass
from abc import ABC

log = logger.setup(name="skopeo")


class CopyException(Exception):
    pass


@dataclass
class ContainerTool(ABC):
    authfile: str = None
    docker_config_dir: str = None


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
            capture_output=True,
            check=True,
            encoding="utf-8",
            env={
                "PATH": os.environ["PATH"],
                "DOCKER_CONFIG": self.docker_config_dir or "",
            },
        )
        return json.loads(inspect_result.stdout)

    @classmethod
    def copy(
        cls,
        src: Image,
        dest: Image,
        digestfile: Path = None,
        src_authfile: Path = None,
        dest_authfile: Path = None,
    ) -> None:
        if not src or not dest:
            raise CopyException(
                f"Missing {'source' if src else 'destination'} from copy command"
            )
        if not src.transport or not dest.transport:
            raise CopyException(
                f"Missing transport for {'source' if src.transport else 'destination'}"
            )

        cmd = ["skopeo", "copy"]
        cmd += ["--digestfile", digestfile] if digestfile else []
        cmd += ["--src-authfile", src_authfile] if src_authfile else []
        cmd += [f"{src.transport}{src}"]
        cmd += ["--dest-authfile", dest_authfile] if dest_authfile else []
        cmd += [f"{dest.transport}{dest}"]

        copy_result = subprocess.run(
            args=cmd,
            capture_output=True,
            check=True,
        )

        return (copy_result.stdout, copy_result.stderr)
