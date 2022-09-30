import os
import signal
import subprocess
from pathlib import Path
import sys
from ironbank.pipeline.container_tools.container_tool import ContainerTool
from ironbank.pipeline.image import Image
from ironbank.pipeline.utils import logger


log = logger.setup(name="buildah")


class Buildah(ContainerTool):
    def inspect(self, image: Image, storage_driver: str = "vfs", format: str = None):
        cmd = [
            "buildah",
            "inspect",
        ]
        cmd += ["--storage-driver", storage_driver] if storage_driver else []
        cmd += ["--format", format] if format else []
        cmd += [str(image)]
        return subprocess.run(args=cmd, check=True, capture_output=True).stdout

    # TODO: add subprocess exception
    def build(
        self,
        context: Path | str = ".",
        build_args: dict = {},
        labels: dict = {},
        format_: str = None,
        log_level: str = None,
        default_mounts_file: Path | str = None,
        storage_driver: str = None,
        tag: Image | str = None,
    ):
        context = context if isinstance(context, Path) else Path(context)
        cmd = [
            "env",
            "-i",
            "BUILDAH_ISOLATION=chroot",
            f"PATH={os.environ['PATH']}",
            "buildah",
            "build",
        ]
        # add build_args
        cmd += self._generate_arg_list_from_env("--build-arg", build_args)
        # add labels
        cmd += self._generate_arg_list_from_env("--label", labels)
        cmd += ["--authfile", self.authfile] if self.authfile else []
        cmd += ["--format", format_] if format_ else []
        cmd += ["--log-level", log_level] if log_level else []
        cmd += (
            ["--default-mounts-file", default_mounts_file]
            if default_mounts_file
            else []
        )
        cmd += ["--storage-driver", storage_driver] if storage_driver else []
        # tag can either be a string or an Image object, cast to string to support both types
        cmd += ["-t", str(tag)] if tag else []
        cmd += [context]

        return subprocess.run(args=cmd, check=True)

        # def handler(signum, frame):
        #     log.error("Terminating build process")
        #     proc.terminate()
        #     sys.exit(1)

        # # handle ctrl+c for local testing
        # signal.signal(signal.SIGINT, handler)

        # # block subprocess until finished
        # while proc.poll() is None:
        #     pass

        # if proc.returncode != 0:
        #     log.error(f"Buildah failed to build the image. Exit code {proc.returncode}")
        #     sys.exit(1)

    # list images
    # list containers
    # delete image
    # delete container
    # run container from image
