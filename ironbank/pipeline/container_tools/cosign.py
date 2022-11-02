#!/usr/bin/env python3

import os
import subprocess
from dataclasses import dataclass, field
from ironbank.pipeline.utils import logger
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.utils.decorators import subprocess_error_handler
from ironbank.pipeline.container_tools.container_tool import ContainerTool

log = logger.setup(name="cosign")


@dataclass
class Cosign(ContainerTool):
    """
    Perform cosign operations
    """

    cosign_cert: str = field(default_factory=lambda : os.environ["COSIGN_CERT"])
    kms_key_arn: str = field(default_factory=lambda : os.environ["KMS_KEY_SHORT_ARN"])
    aws_access_key_id: str = field(default_factory=lambda : os.environ["COSIGN_AWS_ACCESS_KEY_ID"])
    aws_secret_access_key: str = field(default_factory=lambda : os.environ["COSIGN_AWS_SECRET_ACCESS_KEY"])
    aws_region: str = "us-gov-west-1"


    @subprocess_error_handler(logging_message="Cosign.sign failed")
    def sign(self, image: Image | ImageFile, attachment=None) -> None:
        """
        Perform cosign image or image attachment signature
        """
        cmd = [
            "cosign",
            "sign",
        ]
        cmd += ["--key", self.kms_key_arn] if self.kms_key_arn else []
        cmd += ["--cert", self.cosign_cert] if self.cosign_cert else []
        cmd += ["--attachment", attachment] if attachment else []
        cmd += [f"{image.registry}/{image.name}@{image.digest}"]
        log.info("Run Cosign.sign cmd: %s", cmd)
        subprocess.run(
            args=cmd,
            capture_output=True,
            check=True,
            encoding="utf-8",
            env={
                "AWS_ACCESS_KEY_ID": self.aws_access_key_id or "",
                "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key or "",
                "AWS_REGION": self.aws_region,
                **os.environ,
            },
        )

    @subprocess_error_handler(logging_message="Cosign.clean failed")
    def clean(self, image: Image | ImageFile) -> None:
        """
        Remove existing signatures from the image.
        """
        cmd = [
            "cosign",
            "clean",
        ]
        cmd += [f"{image.registry}/{image.name}@{image.digest}"]
        log.info("Run Cosign.clean cmd: %s", cmd)
        subprocess.run(
            args=cmd,
            capture_output=True,
            check=True,
            encoding="utf-8",
            env={
                "AWS_ACCESS_KEY_ID": self.aws_access_key_id or "",
                "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key or "",
                "AWS_REGION": self.aws_region,
                **os.environ,
            },
        )

    @subprocess_error_handler(logging_message="Cosign.attest failed")
    def attest(
        self,
        image: Image | ImageFile,
        predicate_path: str,
        predicate_type: str,
        replace: bool,
    ) -> None:
        """
        Add attestation
        """
        cmd = [
            "cosign",
            "attest",
        ]
        cmd += ["--replace"] if replace else []
        cmd += ["--predicate", predicate_path]
        cmd += ["--type", predicate_type]
        cmd += ["--key", self.kms_key_arn] if self.kms_key_arn else []
        cmd += ["--cert", self.cosign_cert] if self.cosign_cert else []
        cmd += [f"{image.registry}/{image.name}@{image.digest}"]
        log.info("Run Cosign.attest cmd: %s", cmd)
        subprocess.run(
            args=cmd,
            capture_output=True,
            check=True,
            encoding="utf-8",
            env={
                "AWS_ACCESS_KEY_ID": self.aws_access_key_id or "",
                "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key or "",
                "AWS_REGION": self.aws_region,
                **os.environ,
            },
        )
