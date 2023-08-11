#!/usr/bin/env python3

import shutil
import sys
import json
import requests
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from argparse import Namespace, ArgumentParser

from pipeline.container_tools.cosign import Cosign
from pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
    MockImage,
    MockPath,
    MockTempDirectory,
    MockReportParser,
    MockProject,
    MockResponse,
)
from pipeline.scan_report_parsers.anchore import (
    AnchoreCVEFinding,
    AnchoreReportParser,
)
from pipeline.scan_report_parsers.oscap import OscapReportParser, OscapComplianceFinding
from common.utils import logger

log = logger.setup("test_vat_import")

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import vat_import  # noqa E402

TWISTLOCK_DATA = {
    "packages": [
        {"name": "package1", "version": "1.0", "path": "/path/to/package1"},
    ],
    "applications": [
        {"name": "app1", "version": "1.0", "path": "/path/to/app1"},
    ],
    "results": [
        {
            "packageName": "package1",
            "packageVersion": "1.0",
            "severity": "High",
            "id": "CVE-2021-1234",
            "description": "A vulnerability description.",
            "link": "https://example.com/cve/CVE-2021-1234",
            "cvss": 7.8,
            "publishedDate": "2021-07-15",
            "vulnerabilities": [
                {
                    "packageName": "package1",
                    "packageVersion": "1.0",
                    "severity": "High",
                    "id": "CVE-2021-1234",
                    "description": "A vulnerability description for package1.",
                    "link": "https://example.com/cve/CVE-2021-1234",
                    "cvss": 7.8,
                    "publishedDate": "2021-07-15",
                },
                {
                    "packageName": "package2",
                    "packageVersion": "2.5",
                    "severity": "Unimportant",
                    "id": "CVE-2021-5678",
                    "description": "A vulnerability description for package2.",
                    "link": "https://example.com/cve/CVE-2021-5678",
                    "cvss": 2.1,
                    "publishedDate": "2021-08-10",
                },
            ],
        }
    ],
}

SAMPLE_JSON_DATA = {
    "sha123456": {
        "result": {
            "rows": [
                [
                    "image_id_1",
                    "repo/tag:latest",
                    "trigger_id_1",
                    "dockerfile",
                    "trigger_1",
                    "check_output_1",
                    "gate_action_1",
                    {
                        "matched_rule_id": "rule_123",
                        "whitelist_id": "whitelist_123",
                        "whitelist_name": "security_whitelist",
                    },
                    "whitelist_id_1",
                    "inherited_1",
                    "policy_id_1",
                ],
                [
                    "image_id_2",
                    "repo/tag:1.0",
                    "trigger_id_2",
                    "gate_2",
                    "trigger_2",
                    "check_output_2",
                    "gate_action_2",
                    "",
                    "",
                ],
                # Add more rows as needed
            ]
        }
    }
}

mock_args = Namespace(
    oscap=True,
    anchore_sec=True,
    anchore_gates=True,
    twistlock=True,
    container="my_image",
    version="1.0",
    parent="parent_image",
    parent_version="2.0",
    job_id="123",
    digest="abc123",
    timestamp="2023-08-08T12:00:00Z",
    scan_date="2023-08-08T12:00:00Z",
    build_date="2023-08-08T12:00:00Z",
    repo_link="https://github.com/example/repo",
    commit_hash="abcdef123456",
    use_json="",
    api_url="https://mock.com/example/repo",
)


## The purpose of this class is to make MockPath subscriptable. Otherwsie there's no reason this should be in MockClasses
class MockPathExtension(MockPath):
    def __init__(self, path, mock_data):
        self.path = path
        self.mock_data = mock_data

    def __getitem__(self, index):
        return self.mock_data[index]


@patch("vat_import.Path", new=MockPath)
@patch("vat_import.OscapReportParser", new=MockReportParser)
def test_generate_anchore_cve_findings(monkeypatch):
    monkeypatch.setattr(
        AnchoreCVEFinding, "set_truncated_url", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        AnchoreReportParser,
        "get_findings",
        lambda *args, **kwargs: [
            AnchoreCVEFinding(
                "test1",
                severity="high",
                package_path="pkgdb",
                extra={"description": "test1"},
            ),
        ],
    )
    result = vat_import.generate_anchore_cve_findings(
        AnchoreCVEFinding("test1", severity="high", extra={"description": "test1"}),
        ["test1", "test2"],
    )

    assert result == [{"test1": None, "test2": None, "score": ""}]


@patch("vat_import.Path", new=MockPath)
def test_generate_oscap_findings(monkeypatch):
    monkeypatch.setattr(
        OscapReportParser,
        "get_findings",
        lambda *args, **kwargs: [OscapComplianceFinding("test1", severity="high")],
    )
    result = vat_import.generate_oscap_findings(MockPath("test1"), ["test1", "test2"])
    assert result == [{"test1": None, "test2": None}]


@patch("vat_import.Path", new=MockPath)
def test_generate_anchore_comp_findings(monkeypatch):
    monkeypatch.setattr(json, "load", lambda *args, **kwargs: SAMPLE_JSON_DATA)
    result = vat_import.generate_anchore_comp_findings(MockPath("test1"))
    assert result == [
        {
            "finding": "trigger_id_1",
            "severity": "ga_gate_action_1",
            "description": "check_output_1\n Gate: dockerfile\n Trigger: trigger_1\n Policy ID: whitelist_id_1",
            "link": None,
            "score": "",
            "package": None,
            "packagePath": None,
            "scanSource": "anchore_comp",
        },
        {
            "finding": "trigger_id_2",
            "severity": "ga_gate_action_2",
            "description": "check_output_2\n Gate: gate_2\n Trigger: trigger_2\n Policy ID: ",
            "link": None,
            "score": "",
            "package": None,
            "packagePath": None,
            "scanSource": "anchore_comp",
        },
    ]


def test_get_twistlock_package_paths():
    result = vat_import.get_twistlock_package_paths(TWISTLOCK_DATA)
    expected_result = {
        ("package1", "1.0"): {"/path/to/package1"},
        ("app1", "1.0"): {"/path/to/app1"},
    }
    assert result == expected_result


@patch("vat_import.Path", new=MockPath)
def test_generate_twistlock_findings(monkeypatch):
    sample_packages_data = {
        ("package1", "1.0"): ["/path/to/package1_v1", "/path/to/package1_v2"],
        ("package2", "2.5"): ["/path/to/package2_v1"],
    }
    bad_twistlock_data = {
        "results": [
            {
                "vulnerabilities": [
                    {},
                ],
            }
        ],
    }

    monkeypatch.setattr(
        vat_import,
        "get_twistlock_package_paths",
        lambda *args, **kwargs: sample_packages_data,
    )

    log.info("Testing with invalid twistlock data (missing dictionary keys)")
    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            json,
            "loads",
            lambda *args, **kwargs: MockPathExtension(
                path="test", mock_data=bad_twistlock_data
            ),
        )
        vat_import.generate_twistlock_findings(MockPath("test"))

    log.info("Testing with valid mock twistlock data")
    monkeypatch.setattr(
        json,
        "loads",
        lambda *args, **kwargs: MockPathExtension(
            path="test", mock_data=TWISTLOCK_DATA
        ),
    )

    result = vat_import.generate_twistlock_findings(MockPath("test"))
    expected_result = [
        {
            "finding": "CVE-2021-1234",
            "severity": "high",
            "description": "A vulnerability description for package1.",
            "link": "https://example.com/cve/CVE-2021-1234",
            "score": 7.8,
            "package": "package1-1.0",
            "packagePath": "/path/to/package1_v1",
            "scanSource": "twistlock_cve",
            "reportDate": "2021-07-15",
            "identifiers": ["CVE-2021-1234"],
        },
        {
            "finding": "CVE-2021-1234",
            "severity": "high",
            "description": "A vulnerability description for package1.",
            "link": "https://example.com/cve/CVE-2021-1234",
            "score": 7.8,
            "package": "package1-1.0",
            "packagePath": "/path/to/package1_v2",
            "scanSource": "twistlock_cve",
            "reportDate": "2021-07-15",
            "identifiers": ["CVE-2021-1234"],
        },
        {
            "finding": "CVE-2021-5678",
            "severity": "low",
            "description": "A vulnerability description for package2.",
            "link": "https://example.com/cve/CVE-2021-5678",
            "score": 2.1,
            "package": "package2-2.5",
            "packagePath": "/path/to/package2_v1",
            "scanSource": "twistlock_cve",
            "reportDate": "2021-08-10",
            "identifiers": ["CVE-2021-5678"],
        },
    ]
    assert result == expected_result


@patch("vat_import.Path", new=MockPath)
def test_create_api_call(monkeypatch):
    monkeypatch.setenv("ARTIFACT_STORAGE", "mock_ARTIFACT_STORAGE")
    monkeypatch.setenv("IMAGE_TO_SCAN", "mock_IMAGE_TO_SCAN")
    monkeypatch.setattr(ArgumentParser, "parse_args", lambda *args, **kwargs: mock_args)
    monkeypatch.setattr(
        vat_import,
        "generate_oscap_findings",
        lambda *args, **kwargs: [{"test1": None, "test2": None}],
    )

    monkeypatch.setattr(
        vat_import,
        "generate_anchore_cve_findings",
        lambda *args, **kwargs: [{"test1": None, "test2": None, "score": ""}],
    )

    monkeypatch.setattr(
        vat_import, "generate_anchore_comp_findings", lambda *args, **kwargs: [{}]
    )

    monkeypatch.setattr(
        vat_import, "generate_twistlock_findings", lambda *args, **kwargs: [{}]
    )
    log.info("Testing we return the appropriate data when create_api_call is executed")
    result = vat_import.create_api_call()
    assert result == {
        "imageName": "my_image",
        "imageTag": "1.0",
        "parentImageName": "parent_image",
        "parentImageTag": "2.0",
        "jobId": "123",
        "digest": "abc123",
        "timestamp": "2023-08-08T12:00:00Z",
        "scanDate": "2023-08-08T12:00:00Z",
        "buildDate": "2023-08-08T12:00:00Z",
        "repo": {"url": "https://github.com/example/repo", "commit": "abcdef123456"},
        "findings": [
            {},
            {"test1": None, "test2": None, "score": ""},
            {},
            {"test1": None, "test2": None},
        ],
        "keywords": [],
        "tags": [],
        "labels": {},
        "renovateEnabled": True,
    }


@patch("vat_import.Path", new=MockPath)
@patch("vat_import.Image", new=MockImage)
@patch("tempfile.TemporaryDirectory", new=MockTempDirectory)
def test_get_parent_vat_response(monkeypatch):
    monkeypatch.setenv("BASE_REGISTRY", "mock_registry.dso.mil")
    monkeypatch.setenv("DOCKER_AUTH_FILE_PULL", "ZXhhbXBsZQ==")
    monkeypatch.setattr(shutil, "copy", lambda *args, **kwargs: None)
    monkeypatch.setattr(shutil, "move", lambda from_, to_: None)
    mock_hardening_manifest = MockHardeningManifest(".")
    with patch("vat_import.Cosign", new=MagicMock(spec=Cosign)) as mock_cosign:
        vat_import.get_parent_vat_response(".", mock_hardening_manifest)
    mock_cosign.download.assert_called_once()


@patch("vat_import.Path", new=MockPath)
@patch("vat_import.DsopProject", new=MockProject)
@patch("vat_import.HardeningManifest", new=MockHardeningManifest)
def test_main(monkeypatch, raise_):
    monkeypatch.setattr(ArgumentParser, "parse_args", lambda *args, **kwargs: mock_args)
    monkeypatch.setattr(
        vat_import, "get_parent_vat_response", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(json, "load", lambda *args, **kwargs: [])
    monkeypatch.setattr(json, "dump", lambda *args, **kwargs: [])

    monkeypatch.setattr(vat_import, "create_api_call", lambda *args, **kwargs: {})
    monkeypatch.setenv("ARTIFACT_DIR", "mock_ARTIFACT_DIR")
    monkeypatch.setenv("VAT_TOKEN", "mock_VAT_TOKEN")
    log.info(
        "Ensuring the code exits with a requests.exceptions.RequestException for a bad request"
    )
    with pytest.raises(SystemExit):
        vat_import.main()

    log.info("Testing the code exits with a requests.exceptions.RequestException")
    with pytest.raises(SystemExit):
        mock_args.api_url = "https://github.com/example/repo"
        vat_import.main()

    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: raise_(RuntimeError))
    log.info("Testing the system exits when we encounter a runtime error")
    with pytest.raises(SystemExit):
        vat_import.main()

    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: raise_(Exception))
    log.info("System exits for generic exception raised")
    with pytest.raises(SystemExit):
        vat_import.main()

    monkeypatch.setattr(
        requests, "post", lambda *args, **kwargs: MockResponse(status_code=200)
    )

    mock_args.use_json = "yes"
    log.info("Testing for a valid request")
    vat_import.main()


def test_set_log_level(monkeypatch):
    monkeypatch.setenv("LOGLEVEL", "DEBUG")
    vat_import.set_log_level()
    monkeypatch.setenv("LOGLEVEL", "ERROR")
    vat_import.set_log_level()
