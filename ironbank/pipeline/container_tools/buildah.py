import json
import os
import subprocess
from pathlib import Path

from ironbank.pipeline.container_tools.container_tool import ContainerTool
from ironbank.pipeline.image import Image
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.decorators import buildah_error_handler

log = logger.setup(name="buildah")


class Buildah(ContainerTool):
    """A class used to interact with the Buildah container tool."""

    @buildah_error_handler(logging_message="Buildah.inspect failed")
    def inspect(
        self,
        image: Image,
        storage_driver: str = "vfs",
        output_format: str = None,
        log_cmd: bool = False,
    ):
        """Inspects an image using the Buildah tool.

        Parameters
        ----------
        image : Image
            Image object to be inspected.
        storage_driver : str, optional
            Specifies which storage driver is used by Buildah. Defaults to "vfs".
        format : str, optional
            Specifies the output format. If not provided, defaults to JSON.
        log_cmd : bool, optional
            If True, logs the inspect command. Defaults to False.

        Returns
        -------
        dict
            A dictionary containing the image inspection results.
        """
        cmd = [
            "buildah",
            "inspect",
        ]
        cmd += ["--storage-driver", storage_driver] if storage_driver else []
        cmd += ["--format", format] if output_format else []
        cmd += [str(image)]
        if log_cmd:
            log.info(cmd)
        return json.loads(
            subprocess.run(args=cmd, check=True, capture_output=True).stdout
        )

    # TODO: add subprocess exception
    @buildah_error_handler(logging_message="Buildah.build failed")
    def build(
        self,
        context: Path | str = ".",
        build_args: dict = None,
        labels: dict = None,
        format_: str = None,
        log_level: str = None,
        default_mounts_file: Path | str = None,
        storage_driver: str = None,
        tag: Image | str = None,
        ulimit_args: dict = None,
        log_cmd: bool = False,
    ):
        """Builds a Docker image using the Buildah tool.

        Parameters
        ----------
        context : Path | str, optional
            The build context path. Defaults to the current directory.
        build_args : dict, optional
            A dictionary of build arguments.
        labels : dict, optional
            A dictionary of labels to add to the image.
        format_ : str, optional
            Specifies the format of the image. If not provided, uses the default.
        log_level : str, optional
            Sets the logging level. If not provided, uses the default.
        default_mounts_file : Path | str, optional
            Path to the default mounts file.
        storage_driver : str, optional
            Specifies which storage driver is used by Buildah. If not provided, uses the default.
        tag : Image | str, optional
            The tag to apply to the image.
        ulimit_args : dict, optional
            A dictionary of ulimit arguments.
        log_cmd : bool, optional
            If True, logs the build command. Defaults to False.

        Returns
        -------
        subprocess.CompletedProcess
            The result of the 'buildah build' command as a subprocess.CompletedProcess object.
        """
        if build_args is None:
            build_args = {}
        if labels is None:
            labels = {}
        if ulimit_args is None:
            ulimit_args = {}
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
        cmd += self._generate_arg_list_from_env("--ulimit", ulimit_args)
        # tag can either be a string or an Image object, cast to string to support both types
        cmd += ["-t", str(tag)] if tag else []
        cmd += [context]
        if log_cmd:
            log.info(cmd)
        return subprocess.run(args=cmd, check=True)

        #
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
