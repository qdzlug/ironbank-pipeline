#!/usr/bin/env python3
import multiprocessing
import sys
import os
import logging
import pytest
import pathlib
import json
import yaml
import time
import jsonschema
from unittest.mock import patch, mock_open, Mock
from dataclasses import dataclass

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from mocks.mock_classes import MockHardeningManifest
from hardening_manifest import HardeningManifest  # noqa E402

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")

mock_path = pathlib.Path(
    pathlib.Path(__file__).absolute().parent.parent.parent, "mocks"
)


@dataclass
class MockConnection:
    def send(self, message):
        logging.info(f"{message} sent")

    def recv(self):
        logging.info("message received")


@dataclass
class MockProcess:
    alive: bool = True
    exitcode: int = 0

    def start(self):
        return None

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.alive = False


class MockJsonschema(Mock):
    def validate(self, content):
        pass


class MockJsonschemaFailure(Mock):
    def validate(self, content):
        raise jsonschema.ValidationError("invalid schema")


@pytest.fixture
def mock_good_labels():
    return {
        "org.opencontainers.image.title": "ubi8-minimal",
        "org.opencontainers.image.description": "Red Hat Universal Base Images (UBI) \
            are OCI-compliant container base operating system images with complementary \
            runtime languages and packages that are freely redistributable.",
        "org.opencontainers.image.licenses": "Apache v2",
        "org.opencontainers.image.url": "https://catalog.redhat.com/software/container-stacks/detail/5ec53f50ef29fd35586d9a56",  # noqa: E501
        "org.opencontainers.image.vendor": "Red Hat",
        "org.opencontainers.image.version": "8.3",
        "mil.dso.ironbank.image.keywords": "ubi, minimal, base, test",
        "mil.dso.ironbank.image.type": "commercial",
        "mil.dso.ironbank.product.name": "UBI8-minimal",
    }


@pytest.fixture
def mock_bad_labels():
    return {
        "org.opencontainers.image.title": "ubi8-minimal",
        "org.opencontainers.image.description": "Red Hat Universal Base Images (UBI) \
            are OCI-compliant container base operating system images with complementary \
            runtime languages and packages that are freely redistributable.",
        "org.opencontainers.image.licenses": "FIXME",
        "org.opencontainers.image.url": "https://catalog.redhat.com/software/container-stacks/detail/5ec53f50ef29fd35586d9a56",  # noqa: E501
        "org.opencontainers.image.vendor": "Red Hat",
        "org.opencontainers.image.version": "8.3",
        "mil.dso.ironbank.image.keywords": "ubi, minimal, base, test",
        "mil.dso.ironbank.image.type": "commercial",
        "mil.dso.ironbank.product.name": "UBI8-minimal",
    }


@pytest.fixture
def mock_good_maintainers():
    return {
        "name": "Example Examp",
        "username": "example",
        "email": "example@company.com",
    }


@pytest.fixture
def mock_bad_maintainers():
    return {
        "name": "FIXME",
        "username": "example",
        "email": "example@company.com",
    }


@pytest.fixture
def mock_good_image_sources():
    return [
        {
            "tag": "registry.example.com/example:1.0",
            "url": "docker://registry.example.com/example@sha256:4d736d84721c8fa09d5b0f5988da5f34163d407d386cc80b62cbf933ea5124e8",
        },
    ]


@pytest.fixture
def mock_bad_image_sources():
    return [
        {
            "tag": "registry1.dso.mil/example:1.0",
            "url": "docker://registry.example.com/example@sha256:4d736d84721c8fa09d5b0f5988da5f34163d407d386cc80b62cbf933ea5124e8",
        },
        {
            "tag": "registry.example.com/example:1.0",
            "url": "docker://registry1.dso.mil/example@sha256:4d736d84721c8fa09d5b0f5988da5f34163d407d386cc80b62cbf933ea5124e8",
        },
        {
            "tag": "registry1.dso.mil/example:1.0",
            "url": "docker://registry1.dso.mil/example@sha256:4d736d84721c8fa09d5b0f5988da5f34163d407d386cc80b62cbf933ea5124e8",
        },
    ]


@pytest.fixture
def hm():
    return HardeningManifest(
        pathlib.Path(
            mock_path,
            "mock_hardening_manifest.yaml",
        )
    )


@pytest.fixture
def mock_empty():
    def mock_none(_):
        return None

    def mock_empty_arr(_):
        return []

    def mock_empty_str(_):
        return ""

    return {"none": mock_none, "arr": mock_empty_arr, "str": mock_empty_str}


def test_init(monkeypatch, caplog):
    def mock_validate(_):
        logging.info("validated")

    monkeypatch.setattr(HardeningManifest, "validate", mock_validate)
    hm_path = pathlib.Path(
        mock_path,
        "mock_hardening_manifest.yaml",
    )
    HardeningManifest(hm_path)
    assert "validated" not in caplog.text
    caplog.clear()
    HardeningManifest(hm_path, validate=True)
    assert "validated" in caplog.text


def test_validate(monkeypatch, caplog, hm, mock_empty):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(
        HardeningManifest, "validate_schema_with_timeout", mock_empty["none"]
    )
    monkeypatch.setattr(HardeningManifest, "reject_invalid_labels", mock_empty["arr"])
    monkeypatch.setattr(
        HardeningManifest, "reject_invalid_maintainers", mock_empty["arr"]
    )
    monkeypatch.setattr(
        HardeningManifest, "reject_invalid_image_sources", mock_empty["arr"]
    )
    hm.validate()
    logging.info(caplog.text)
    assert "Checking for" in caplog.text
    caplog.clear()


@patch.dict(os.environ, {"HM_VERIFY_TIMEOUT": "1"})
def test_validate_schema_with_timeout(monkeypatch, caplog, hm):
    def mock_pipe():
        return (MockConnection(), MockConnection())

    def mock_successful_process(target="", args=()):
        return MockProcess(alive=False)

    def mock_backtracking_process(target="", args=()):
        return MockProcess()

    def mock_failed_process(target="", args=()):
        return MockProcess(alive=False, exitcode=1)

    def mock_sleep(val):
        pass

    caplog.set_level(logging.INFO)
    monkeypatch.setattr(time, "sleep", mock_sleep)

    logging.info("It should successfully validate the hardening manifest")
    monkeypatch.setattr(multiprocessing, "Pipe", mock_pipe)
    monkeypatch.setattr(multiprocessing, "Process", mock_successful_process)
    hm.validate_schema_with_timeout()
    for record in caplog.records:
        assert record.levelname != "ERROR" and record.levelname != "WARNING"
    caplog.clear()

    with pytest.raises(SystemExit) as exc_info1:
        logging.info("It should cause catastrophic backtracking")
        monkeypatch.setattr(multiprocessing, "Process", mock_backtracking_process)
        hm.validate_schema_with_timeout()
    assert exc_info1.type == SystemExit
    assert "Hardening Manifest validation timeout exceeded" in caplog.text
    caplog.clear()

    with pytest.raises(SystemExit) as exc_info2:
        logging.info("It should fail to validate the hardening manifest")
        monkeypatch.setattr(multiprocessing, "Process", mock_failed_process)
        hm.validate_schema_with_timeout()
    assert exc_info2.type == SystemExit
    assert "Hardening Manifest failed jsonschema validation" in caplog.text
    caplog.clear()


def test_validate_schema(monkeypatch, caplog, hm):
    def mock_yaml_load(f):
        # intentionally returning str instead of dict from yaml to ensure jsonschema is being mocked correctly
        return "a"

    def mock_json_load(f):
        return {"properties": {"labels": {"patternProperties": ""}}}

    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    monkeypatch.setattr(yaml, "safe_load", mock_yaml_load)
    monkeypatch.setattr(json, "load", mock_json_load)
    # mocking instance method: jsonschema.Draft201909Validator().validate()
    logging.info("It should successfully validate the schema")
    with patch(target="jsonschema.Draft201909Validator", new=MockJsonschema):
        hm.validate_schema(MockConnection())

        logging.info(
            "It should successfully validate the schema, and pattern properties"
        )
        with patch.dict(
            os.environ, {"LABEL_ALLOWLIST_REGEX": r"^mil\.dso\.ironbank\.os-type$"}
        ):
            hm.validate_schema(MockConnection())

    logging.info("It should exit on schema validation errors")
    with pytest.raises(SystemExit) as exc_info:
        with patch("jsonschema.Draft201909Validator", new=MockJsonschemaFailure):
            hm.validate_schema(MockConnection())
    assert exc_info.type == SystemExit


def test_find_fixme(
    hm, mock_good_labels, mock_good_maintainers, mock_bad_labels, mock_bad_maintainers
):
    assert hm.check_for_fixme(mock_good_labels) == []
    assert hm.check_for_fixme(mock_good_maintainers) == []
    assert hm.check_for_fixme(mock_bad_labels) == ["org.opencontainers.image.licenses"]
    assert hm.check_for_fixme(mock_bad_maintainers) == ["name"]


def test_reject_invalid_labels(
    monkeypatch, caplog, hm, mock_good_labels, mock_bad_labels
):
    def mock_good_check_for_fixme(_, subcontent):
        return []

    def mock_bad_check_for_fixme(_, subcontent):
        return subcontent.keys()

    logging.info("It should accept valid labels")
    monkeypatch.setattr(HardeningManifest, "check_for_fixme", mock_good_check_for_fixme)
    assert hm.reject_invalid_labels(mock_good_labels) == []

    logging.info("It should reject invalid labels")
    monkeypatch.setattr(HardeningManifest, "check_for_fixme", mock_bad_check_for_fixme)
    assert hm.reject_invalid_labels(mock_bad_labels) == mock_bad_labels.keys()
    assert "FIXME found in" in caplog.text
    caplog.clear()


def test_check_for_invalid_image_source(
    hm, mock_good_image_sources, mock_bad_image_sources
):
    logging.info("It should accept valid image sources")
    for image_source in mock_good_image_sources:
        assert hm.check_for_invalid_image_source(image_source) is None

    logging.info("It should reject invalid image sources")
    assert (
        hm.check_for_invalid_image_source(mock_bad_image_sources[0])
        == mock_bad_image_sources[0]["tag"]
    )
    assert (
        hm.check_for_invalid_image_source(mock_bad_image_sources[1])
        == mock_bad_image_sources[1]["url"]
    )
    # should return first value fourd
    assert (
        hm.check_for_invalid_image_source(mock_bad_image_sources[2])
        == mock_bad_image_sources[2]["tag"]
    )


@pytest.mark.only
def test_reject_invalid_image_sources(monkeypatch, mock_good_image_sources):
    monkeypatch.setattr(
        HardeningManifest, "check_for_invalid_image_source", lambda x, y: []
    )
    mock_hm = MockHardeningManifest(resources=mock_good_image_sources)
    invalid_sources = mock_hm.reject_invalid_image_sources()
    assert invalid_sources == []
