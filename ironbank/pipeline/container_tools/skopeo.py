import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ironbank.pipeline.container_tools.container_tool import ContainerTool
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.decorators import subprocess_error_handler

log = logger.setup(name="skopeo")


class CopyException(Exception):
    """Copy Exception."""


@dataclass
class Skopeo(ContainerTool):
    @subprocess_error_handler(logging_message="Skopeo.inspect failed")
    def inspect(
        self, image: Image | ImageFile, raw: bool = False, log_cmd: bool = False
    ) -> dict:
        # use tag by default, else use digest
        cmd = [
            "skopeo",
            "inspect",
        ]
        cmd += ["--authfile", self.authfile] if self.authfile else []
        cmd += ["--raw"] if raw else []
        cmd += [
            f"{image}",
        ]

        if log_cmd:
            log.info(cmd)
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
    def copy(
        self,
        src: Image | ImageFile,
        dest: Image | ImageFile,
        digestfile: Path = None,
        src_authfile: Path = None,
        dest_authfile: Path = None,
        remove_signatures: bool = False,
        additional_tags: str | list[str] = [],
        src_creds: str = None,
        dest_creds: str = None,
        log_cmd: bool = False,
    ) -> None:
        """Copies an image from a source to a destination using the Skopeo
        utility.

        Parameters:
        src: Source image or file.
        dest: Destination image or file.
        digestfile: Path to the digest file.
        src_authfile: Path to the auth file for the source.
        dest_authfile: Path to the auth file for the destination.
        remove_signatures: Whether to remove signatures from the image.
        additional_tags: Additional tags for the image, can be a string or list of strings.
        src_creds: Credentials for the source.
        dest_creds: Credentials for the destination.
        log_cmd: Whether to log the command.

        Raises:
        CopyException: If source or destination, or their transports are missing.

        Returns:
        The standard output and error output from the Skopeo copy command.
        """
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
        cmd += ["--authfile", self.authfile] if self.authfile else []
        cmd += ["--remove-signatures"] if remove_signatures else []
        # get additional tags
        tags = ["--additional-tag", additional_tags]
        cmd += (
            tags
            if isinstance(additional_tags, str)
            else self._generate_arg_list_from_list(*tags)
        )
        cmd += ["--src-authfile", src_authfile] if src_authfile else []
        cmd += [f"{src}"]
        cmd += ["--dest-authfile", dest_authfile] if dest_authfile else []
        cmd += [f"{dest}"]
        # Log cmd before adding creds
        if log_cmd:
            log.info(cmd)
        cmd += ["--src-creds", src_creds] if src_creds else []
        cmd += ["--dest-creds", dest_creds] if dest_creds else []

        copy_result = subprocess.run(
            args=cmd,
            check=True,
        )

        return (copy_result.stdout, copy_result.stderr)
