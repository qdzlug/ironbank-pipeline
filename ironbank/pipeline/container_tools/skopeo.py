import os
import json
import subprocess
from pathlib import Path

from ironbank.pipeline.utils import logger
from ironbank.pipeline.container_tools.container_tool import ContainerTool
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.utils.decorators import subprocess_error_handler
from dataclasses import dataclass

log = logger.setup(name="skopeo")


class CopyException(Exception):
    pass


@dataclass
class Skopeo(ContainerTool):
    @subprocess_error_handler(logging_message="Skopeo.inspect failed")
    def inspect(self, image: Image | ImageFile, raw: bool = False) -> dict:
        # use tag by default, else use digest
        cmd = [
            "skopeo",
            "inspect",
        ]
        cmd += ["--authfile"] if self.authfile else []
        cmd += ["--raw"] if raw else []
        cmd += [
            f"{image}",
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
        return json.loads(inspect_result.stdout) if not raw else inspect_result.stdout

    @subprocess_error_handler(logging_message="Skopeo.copy failed")
    @classmethod
    def copy(
        cls,
        src: Image | ImageFile,
        dest: Image | ImageFile,
        digestfile: Path = None,
        src_authfile: Path = None,
        dest_authfile: Path = None,
        remove_signatures: bool = False,
        additional_tags: str | list[str] = [],
        src_creds: str = None,
        dest_creds: str = None,
    ) -> None:
        if not src or not dest:
            # TODO: Figure out why it isn't logging
            raise CopyException(
                f"Missing {'source' if not src else 'destination'} from copy command"
            )
        if not src.transport or not dest.transport:
            raise CopyException(
                f"Missing transport for {'source' if not src.transport else 'destination'}"
            )

        cmd = ["skopeo", "copy"]
        cmd += ["--digestfile", digestfile] if digestfile else []
        cmd += ["--authfile", cls.authfile] if cls.authfile else []
        cmd += ["--remove-signatures"] if remove_signatures else []
        # get additional tags
        tags = ["--additional-tag", additional_tags]
        cmd += (
            tags
            if type(additional_tags) == str
            else cls._generate_arg_list_from_list(*tags)
        )
        cmd += ["--src-creds", src_creds] if src_creds else []
        cmd += ["--dest-creds", dest_creds] if dest_creds else []
        cmd += ["--src-authfile", src_authfile] if src_authfile else []
        cmd += [f"{src}"]
        cmd += ["--dest-authfile", dest_authfile] if dest_authfile else []
        cmd += [f"{dest}"]

        copy_result = subprocess.run(
            args=cmd,
            check=True,
        )

        return (copy_result.stdout, copy_result.stderr)
