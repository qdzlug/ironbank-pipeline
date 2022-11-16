#!/usr/bin/env python3

import pytest
import subprocess
from dataclasses import dataclass
from ironbank.pipeline.image import Image
from ironbank.pipeline.utils import logger
from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.utils.exceptions import GenericSubprocessError


log = logger.setup("test_cosign")


@dataclass
class MockSubprocessReturn:
    stdout: str = "standard out"


def mock_subprocess_run(*args, **kwargs):
    return MockSubprocessReturn("data")


def mock_subprocess_fail(*args, **kwargs):
    raise subprocess.CalledProcessError(1, ["cmd"])


def test_cosign_sign(monkeypatch, caplog):
    monkeypatch.setenv("COSIGN_CERT", "cert")
    monkeypatch.setenv("KMS_KEY_SHORT_ARN", "kmsKey")
    monkeypatch.setenv("COSIGN_AWS_ACCESS_KEY_ID", "awsAccessKey")
    monkeypatch.setenv("COSIGN_AWS_SECRET_ACCESS_KEY", "awsSecretKey")

    image = Image(registry="testRegistry", name="testName", digest="testDigest")
    cosign = Cosign()

    log.info("Test sign successful")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    cosign.sign(image, log_cmd=True)
    assert (
        "['cosign', 'sign', '--key', 'kmsKey', '--cert', 'cert', 'testRegistry/testName@testDigest']"
        in caplog.text
    )
    caplog.clear()

    log.info("Test sign attachment")
    cosign.sign(image, attachment="testAttachment", log_cmd=True)
    assert (
        "['cosign', 'sign', '--key', 'kmsKey', '--cert', 'cert', '--attachment', 'testAttachment', 'testRegistry/testName@testDigest']"
        in caplog.text
    )
    caplog.clear()

    log.info("Test sign throw exception")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_fail)
    with pytest.raises(GenericSubprocessError):
        cosign.sign(image)
    assert "Cosign.sign failed" in caplog.text
    caplog.clear()


def test_cosign_clean(monkeypatch, caplog):
    monkeypatch.setenv("COSIGN_CERT", "cert")
    monkeypatch.setenv("KMS_KEY_SHORT_ARN", "kmsKey")
    monkeypatch.setenv("COSIGN_AWS_ACCESS_KEY_ID", "awsAccessKey")
    monkeypatch.setenv("COSIGN_AWS_SECRET_ACCESS_KEY", "awsSecretKey")

    image = Image(registry="testRegistry", name="testName", digest="testDigest")
    cosign = Cosign()

    log.info("Test clean successful")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    cosign.clean(image, log_cmd=True)
    assert "['cosign', 'clean', 'testRegistry/testName@testDigest']" in caplog.text
    caplog.clear()

    log.info("Test clean throw exception")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_fail)
    with pytest.raises(GenericSubprocessError):
        cosign.clean(image)
    assert "Cosign.clean failed" in caplog.text
    caplog.clear()


def test_cosign_attest(monkeypatch, caplog):
    monkeypatch.setenv("COSIGN_CERT", "cert")
    monkeypatch.setenv("KMS_KEY_SHORT_ARN", "kmsKey")
    monkeypatch.setenv("COSIGN_AWS_ACCESS_KEY_ID", "awsAccessKey")
    monkeypatch.setenv("COSIGN_AWS_SECRET_ACCESS_KEY", "awsSecretKey")

    image = Image(registry="testRegistry", name="testName", digest="testDigest")
    cosign = Cosign()

    log.info("Test attest successful")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    cosign.attest(
        image=image,
        predicate_path="testPath",
        predicate_type="testType",
        replace=False,
        log_cmd=True,
    )
    assert (
        "['cosign', 'attest', '--predicate', 'testPath', '--type', 'testType', '--key', 'kmsKey', '--cert', 'cert', 'testRegistry/testName@testDigest']"
        in caplog.text
    )
    caplog.clear()

    log.info("Test attest replace")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    cosign.attest(
        image=image,
        predicate_path="testPath",
        predicate_type="testType",
        replace=True,
        log_cmd=True,
    )
    assert (
        "['cosign', 'attest', '--replace', '--predicate', 'testPath', '--type', 'testType', '--key', 'kmsKey', '--cert', 'cert', 'testRegistry/testName@testDigest']"
        in caplog.text
    )
    caplog.clear()

    log.info("Test attest throw exception")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_fail)
    with pytest.raises(GenericSubprocessError):
        cosign.attest(
            image=image,
            predicate_path="testPath",
            predicate_type="testType",
            replace=False,
        )
    assert "Cosign.attest failed" in caplog.text
    caplog.clear()
