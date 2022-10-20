import os
import json
import subprocess
from pathlib import Path

from ironbank.pipeline.utils import logger
from ironbank.pipeline.container_tools.container_tool import ContainerTool
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.utils.decorators import subprocess_error_handler
from dataclasses import dataclass

log = logger.setup(name="cosign")

@dataclass
class Cosign(ContainerTool):
    """
    Perform cosign operations
    """
    image: Image
    cosign_cert: str
    kms_key_arn: str
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_region: str = "us-gov-west-1"

    def sign_image(cls) -> None:
        """
        Perform cosign image signature
        """
        log.info(
            f"Signing image: {cls.image.registry}/{cls.image.name}@{cls.image.digest}"
        )
        sign_cmd = [
            "cosign",
            "sign",
            "--key",
            cls.kms_key_arn,
            "--cert",
            cls.cosign_cert,
            f"{cls.image.registry}/{cls.image.name}@{cls.image.digest}",
        ]
        log.info(" ".join(sign_cmd))
        try:
            subprocess.run(
                args=sign_cmd,
                check=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "AWS_ACCESS_KEY_ID": cls.aws_access_key_id,
                    "AWS_SECRET_ACCESS_KEY": cls.aws_secret_access_key,
                    "AWS_REGION": cls.aws_region,
                    **os.environ,
                },
            )
        except subprocess.CalledProcessError:
            log.error(
                f"Failed to sign image: {cls.image.registry}/{cls.image.name}@{cls.image.digest}"
            )
            sys.exit(1)

    def remove_existing_signatures(cls) -> None:
        """
        Remove existing signatures from the image.
        """
        log.info(
            f"Removing existing signatures from image: {cls.image.registry}/{cls.image.name}@{cls.image.digest}"
        )
        sign_cmd = [
            "cosign",
            "clean",
            f"{cls.image.registry}/{cls.image.name}@{cls.image.digest}",
        ]
        log.info(" ".join(sign_cmd))
        try:
            subprocess.run(
                args=sign_cmd,
                check=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "AWS_ACCESS_KEY_ID": cls.aws_access_key_id,
                    "AWS_SECRET_ACCESS_KEY": cls.aws_secret_access_key,
                    "AWS_REGION": cls.aws_region,
                    **os.environ,
                },
            )
        except subprocess.CalledProcessError:
            pass

    def sign_image_attachment(cls, attachment_type) -> None:
        """
        Perform cosign image attachment signature
        """
        log.info(
            f"Signing {attachment_type}: {cls.image.registry}/{cls.image.name}@{cls.image.digest}"
        )
        sign_cmd = [
            "cosign",
            "sign",
            "--key",
            cls.kms_key_arn,
            "--cert",
            cls.cosign_cert,
            f"--attachment={attachment_type}",
            f"{cls.image.registry}/{cls.image.name}@{cls.image.digest}",
        ]
        log.info(" ".join(sign_cmd))
        try:
            subprocess.run(
                args=sign_cmd,
                check=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "AWS_ACCESS_KEY_ID": cls.aws_access_key_id,
                    "AWS_SECRET_ACCESS_KEY": cls.aws_secret_access_key,
                    "AWS_REGION": cls.aws_region,
                    **os.environ,
                },
            )
        except subprocess.CalledProcessError:
            log.error(
                f"Failed to sign {attachment_type}: {cls.image.registry}/{cls.image.name}@{cls.image.digest}"
            )
            sys.exit(1)

    def add_attestation(cls, predicate_path: str, predicate_type: str) -> None:
        """
        Add attestation
        """
        log.info(
            f"Pushing attestation {predicate_path} with type of {predicate_type}"
        )
        cmd = [
            "cosign",
            "attest",
            "--replace",
            "--predicate",
            predicate_path,
            "--type",
            f"{predicate_type}",
            "--key",
            cls.kms_key_arn,
            "--cert",
            cls.cosign_cert,
            f"{cls.image.registry}/{cls.image.name}@{cls.image.digest}",
        ]
        log.info(" ".join(cmd))
        try:
            subprocess.run(
                args=cmd,
                check=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "AWS_ACCESS_KEY_ID": cls.aws_access_key_id,
                    "AWS_SECRET_ACCESS_KEY": cls.aws_secret_access_key,
                    "AWS_REGION": cls.aws_region,
                    **os.environ,
                },
            )
        except subprocess.CalledProcessError as exception:
            log.error(f"Failed to add attestation {predicate_path}")
            log.error(exception)
            sys.exit(1)