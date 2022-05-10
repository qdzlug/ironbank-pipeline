#!/usr/bin/env python3
from dataclasses import dataclass
import multiprocessing
import sys
import os
import logging
import pytest
from pathlib import Path
from unittest import mock

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hardening_manifest import HardeningManifest  # noqa E402

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")


@pytest.fixture
def load_good_labels():
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
def load_bad_labels():
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
def load_good_maintainers():
    return {
        "name": "Example Examp",
        "username": "example",
        "email": "example@company.com",
    }


@pytest.fixture
def load_bad_maintainers():
    return {
        "name": "FIXME",
        "username": "example",
        "email": "example@company.com",
    }


@pytest.fixture
def hm():
    return HardeningManifest(
        Path(Path(__file__).absolute().parent, "mocks/mock_hardening_manifest.yaml")
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


def test_find_fixme(
    hm, load_good_labels, load_good_maintainers, load_bad_labels, load_bad_maintainers
):
    assert hm.check_for_fixme(load_good_labels) == []
    assert hm.check_for_fixme(load_good_maintainers) == []
    assert hm.check_for_fixme(load_bad_labels) == ["org.opencontainers.image.licenses"]
    assert hm.check_for_fixme(load_bad_maintainers) == ["name"]


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


@dataclass
class MockProcess:
    alive: bool = True
    exitcode: int = 0

    def recv(self):
        return None

    def start(self):
        return None

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.alive = False


@mock.patch.dict(os.environ, {"HM_VERIFY_TIMEOUT": "1"})
def test_validate_schema_with_timeout(monkeypatch, caplog, hm):
    def mock_pipe():
        return (MockProcess(), MockProcess())

    def mock_successful_process(target="", args=()):
        return MockProcess(alive=False)

    def mock_backtracking_process(target="", args=()):
        return MockProcess()

    def mock_failed_process(target="", args=()):
        return MockProcess(alive=False, exitcode=1)

    caplog.set_level(logging.INFO)

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
