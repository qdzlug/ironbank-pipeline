#!/usr/bin/env python3

import base64
import json
from unittest.mock import patch
import pytest
import subprocess
from dataclasses import dataclass
from ironbank.pipeline.image import Image
from ironbank.pipeline.test.mocks.mock_classes import (
    MockImage,
    MockOutput,
    MockPath,
    MockPopen,
)
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


mock_predicate = {"https://hardening_manifest.eg/test/docs": "hardening_manifest.test"}


@patch("ironbank.pipeline.container_tools.cosign.Path", new=MockPath)
# patch instead of monkeypatch to avoid direct import of cosign module
@patch(
    "ironbank.pipeline.container_tools.cosign.Predicates.get_predicate_files",
    new=lambda x: mock_predicate,
)
def test_cosign_download(caplog, monkeypatch):
    log.info("Test failed download")
    mock_output_dir = MockPath("./example")
    mock_docker_conf_dir = MockPath("./")

    mock_image = MockImage(registry="registry1.example", name="example/test", tag="1.0")

    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: MockPopen(
            stdout=MockOutput(mock_data=[]), poll_counter=0, returncode=1
        ),
    )
    monkeypatch.setattr(json, "loads", lambda x: x)
    monkeypatch.setattr(base64, "b64decode", lambda x: x)
    with pytest.raises(GenericSubprocessError):
        Cosign.download(
            image=mock_image,
            output_dir=mock_output_dir,
            docker_config_dir=mock_docker_conf_dir,
            predicate_types=list(mock_predicate.keys()),
        )
    assert "Failed to download attestation" in caplog.text
    caplog.clear()

    log.info("Test successful download")
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: MockPopen(
            stdout=MockOutput(
                mock_data=[
                    {
                        "payload": {
                            "predicateType": list(mock_predicate.keys())[0],
                            "predicate": "exampletext",
                        }
                    },
                    {
                        "payload": {
                            "predicateType": "skipped_predicate_type_example",
                            "predicate": "skipped_predicate_example",
                        }
                    },
                ]
            ),
            poll_counter=0,
        ),
    )
    found_predicates = []
    monkeypatch.setattr(
        json, "dump", lambda x, *args, **kwargs: found_predicates.append(x)
    )

    Cosign.download(
        image=mock_image,
        output_dir=mock_output_dir,
        docker_config_dir=mock_docker_conf_dir,
        predicate_types=list(mock_predicate.keys()),
        log_cmd=True,
    )
    assert found_predicates == ["exampletext"]
    assert str(["cosign", "download", "attestation", str(mock_image)]) in caplog.text
    caplog.clear()


@patch("ironbank.pipeline.container_tools.cosign.Path", new=MockPath)
def test_cosign_verify(caplog, monkeypatch):
    log.info("Test failed signature validation")
    mock_image = MockImage(registry="registry1.example", name="example/test", tag="1.0")
    mock_pubkey = MockPath("/fake/fake.pub")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_fail)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: MockPopen(
            stdout=MockOutput(mock_data=[]), poll_counter=0, returncode=1
        ),
    )
    with pytest.raises(GenericSubprocessError):
        Cosign.verify(image=mock_image, pubkey=mock_pubkey)
    assert "Cosign.verify failed" in caplog.text
    caplog.clear()

    log.info("Test successful download")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    Cosign.verify(image=mock_image, pubkey=mock_pubkey)
    assert f"{str(mock_image)} Verified" in caplog.text
    caplog.clear()
