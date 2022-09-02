from distutils.command.build import build
import os
from pathlib import Path
from ironbank.pipeline.container_tools.container_tool import ContainerTool
from ironbank.pipeline.image import Image
from ironbank.pipeline.utils import logger


log = logger.setup(name="buildah")


class Buildah(ContainerTool):
    def inspect(self, image: Image):
        pass

    def build(
        self,
        build_args: dict,
        labels: dict,
        image_format: str,
        log_level: str,
        default_mounts_file: Path | str,
        storage_driver: str,
        name_tag: str,
    ):
        cmd = [
            "env",
            "-i",
            "BUILDAH_ISOLATION=chroot",
            f"PATH={os.environ['PATH']}",
            "buildah",
            "build",
        ]
        # add build_args, get sub lists of [--build-args, k=v] and flatten list
        cmd += [
            element
            for sub_list in [
                ["--build-args", f"{k}={v}"] for k, v in build_args.items()
            ]
            for element in sub_list
        ]
        # add labels, get sub lists of [--build-args, k=v] and flatten list
        cmd += [
            element
            for sub_list in [["--label", f"{k}={v}"] for k, v in labels.items()]
            for element in sub_list
        ]
        cmd += [
            "--authfile",
            self.authfile,
            "--format",
            image_format,
            "--log-level",
            log_level,
            "--default-mounts-file",
            default_mounts_file,
            "--storage-driver",
            storage_driver,
            "-t",
            name_tag,
        ]
