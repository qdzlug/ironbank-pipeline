#!/usr/bin/env python3

import os
import json
import base64
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from ironbank.pipeline.utils import logger
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.utils.predicates import Predicates
from ironbank.pipeline.utils.decorators import subprocess_error_handler
from ironbank.pipeline.container_tools.container_tool import ContainerTool


@dataclass
class Cosign(ContainerTool):
    """
    Perform cosign operations
    """

    log = logger.setup(name="cosign")
    cosign_cert: str = field(default_factory=lambda: os.environ["COSIGN_CERT"])
    kms_key_arn: str = field(default_factory=lambda: os.environ["KMS_KEY_SHORT_ARN"])
    aws_access_key_id: str = field(
        default_factory=lambda: os.environ["COSIGN_AWS_ACCESS_KEY_ID"]
    )
    aws_secret_access_key: str = field(
        default_factory=lambda: os.environ["COSIGN_AWS_SECRET_ACCESS_KEY"]
    )
    aws_region: str = "us-gov-west-1"

    @subprocess_error_handler(logging_message="Cosign.sign failed")
    def sign(
        self, image: Image | ImageFile, attachment=None, log_cmd: bool = False
    ) -> None:
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
        cmd += [f"{image.digest_str()}"]
        if log_cmd:
            self.log.info(cmd)
        subprocess.run(
            args=cmd,
            capture_output=True,
            check=True,
            encoding="utf-8",
            env={
                "AWS_ACCESS_KEY_ID": self.aws_access_key_id or "",
                "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key or "",
                "AWS_REGION": self.aws_region,
                "DOCKER_CONFIG": self.docker_config_dir,
                **os.environ,
            },
        )

    @subprocess_error_handler(logging_message="Cosign.clean failed")
    def clean(self, image: Image | ImageFile, log_cmd: bool = False) -> None:
        """
        Remove existing signatures from the image.
        """
        cmd = [
            "cosign",
            "clean",
        ]
        cmd += [f"{image.registry}/{image.name}@{image.digest}"]
        if log_cmd:
            self.log.info(cmd)
        subprocess.run(
            args=cmd,
            capture_output=True,
            check=True,
            encoding="utf-8",
            env={
                "AWS_ACCESS_KEY_ID": self.aws_access_key_id or "",
                "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key or "",
                "AWS_REGION": self.aws_region,
                "DOCKER_CONFIG": self.docker_config_dir,
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
        log_cmd: bool = False,
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
        if log_cmd:
            self.log.info(cmd)
        subprocess.run(
            args=cmd,
            capture_output=True,
            check=True,
            encoding="utf-8",
            env={
                "AWS_ACCESS_KEY_ID": self.aws_access_key_id or "",
                "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key or "",
                "AWS_REGION": self.aws_region,
                "DOCKER_CONFIG": self.docker_config_dir,
                **os.environ,
            },
        )

    @classmethod
    @subprocess_error_handler("Failed to download attestation")
    def download(
        cls,
        image: Image,
        output_dir: str,
        docker_config_dir: str,
        predicate_types: list[str],
        log_cmd: bool = False,
    ) -> None:
        # predicate types/files can be found in ironbank/pipeline/utils/predicates.py
        predicates = Predicates()
        predicate_files = predicates.get_predicate_files()
        cmd = [
            "cosign",
            "download",
            "attestation",
            str(image),
        ]
        if log_cmd:
            cls.log.info(cmd)
        proc = subprocess.Popen(
            cmd,
            encoding="utf-8",
            cwd=output_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": os.environ["PATH"],
                "DOCKER_CONFIG": docker_config_dir,
            },
        )
        # Check if child process has terminated and no data piped to stdout

        for line in iter(proc.stdout.readline, ""):
            payload = json.loads(line)["payload"]
            predicate = json.loads(base64.b64decode(payload))

            # payload can take up a lot of memory, delete after decoding and converting to dict object
            del payload

            # Write predicates to their respective files
            for predicate_type in predicate_types:
                if predicate["predicateType"] == predicate_type:
                    with Path(output_dir, predicate_files[predicate_type]).open(
                        "w+"
                    ) as f:
                        json.dump(predicate["predicate"], f, indent=4)
        if proc.poll() != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd)

    @classmethod
    @subprocess_error_handler("Cosign.verify failed")
    def verify(
        cls,
        image: Image,
        pubkey: str = None,
        log_cmd: bool = False,
    ):
        # cmd = [
        #     "cosign",
        #     "verify",
        # ]
        cmd = ["--key", pubkey] if pubkey else [
            "${pwd}",    
        ]
            # "--certificate",
            # "~/ironbank-pipeline/scripts/cosign/cosign-certificate.pem",
            # "--certificate-chain",
            # "~/ironbank-pipeline/scripts/cosign/cosign-ca-bundle.pem",
            # "--signature-digest-algorithm=sha256"]
        # cmd += [f"{image.name}"]
        # if log_cmd:
        cls.log.info(cmd)

        subprocess.run(
            args=cmd,
            capture_output=True,
            check=True,
            encoding="utf-8",
        )
        cls.log.info("%s Verified", image.name)
        return True
