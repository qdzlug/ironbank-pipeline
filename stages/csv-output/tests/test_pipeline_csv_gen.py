#!/usr/bin/env python3

from io import TextIOWrapper
import json
import sys
from typing import Any, Iterable
from unittest.mock import patch
import os
from ironbank.pipeline.scan_report_parsers.oscap import (
    OscapComplianceFinding,
    OscapReportParser,
)
from ironbank.pipeline.scan_report_parsers.anchore import (
    AnchoreReportParser,
    AnchoreCVEFinding,
)
from ironbank.pipeline.test.mocks.mock_classes import (
    MockImage,
    MockOutput,
    MockPath,
    MockPopen,
)
from unittest.mock import mock_open

from pathlib import Path
from ironbank.pipeline.utils import logger
from dataclasses import dataclass

import pytest
import csv
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.scan_report_parsers.report_parser import ReportParser

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pipeline_csv_gen  # noqa E402

log = logger.setup("test_pipeline_csv_gen")


MOCK_ANCHORE_FINDINGS: list[AnchoreCVEFinding] = [
    AnchoreCVEFinding(
        identifier="test1", severity="test1", extra={"description": "test1"}
    ),
    AnchoreCVEFinding(
        identifier="test2", severity="test2", extra={"description": "test2"}
    ),
]

MOCK_OSCAP_FINDINGS: list[OscapComplianceFinding] = [
    OscapComplianceFinding(identifier="test1", severity="test1", result="fail"),
    OscapComplianceFinding(identifier="test2", severity="test2", result="notchecked"),
]

MOCK_TWISTLOCK_CVE_REPORT: dict = {
    "results": [
        {
            "vulnerabilities": [
                {
                    "id": "t_id",
                    "severity": "t_sev",
                    "packageName": "t_pkg_name",
                    "packageVersion": "t_pkg_ver",
                }
            ]
        }
    ]
}

MOCK_ANCHORE_REPORT: dict = {
    "t_sha": {
        "result": {
            "rows": [
                [
                    "t_sha",
                    "test/123",
                    "456",
                    "dockerfile",
                    "package",
                    "User root found",
                    "stop",
                    False,
                    "TestEffectiveUserChecks",
                    "",
                ],
                [
                    "t_sha",
                    "test/123",
                    "456",
                    "dockerfile",
                    "package",
                    "User root found",
                    "go",
                    {
                        "matched_rule_id": "1",
                        "whitelist_id": "CommonSUIDFilesWhitelist",
                        "whitelist_name": "Common RHEL DEB SUID Files",
                    },
                    "TestEffectiveUserChecks",
                    "",
                ],
            ]
        }
    }
}


@dataclass
class MockWriter:
    file_: TextIOWrapper = None
    fieldnames: list[str] = None
    rows: list[Iterable[Any]] = None

    def writerow(self, row: Iterable[Any]):
        if not self.rows:
            self.rows = []
        self.rows.append(row)


@pytest.mark.only
def test_generate_anchore_cve_report(monkeypatch):
    log.info("Test successful anchore cve report generated")
    monkeypatch.setattr(Path, "open", mock_open())
    monkeypatch.setattr(
        AnchoreReportParser,
        "get_findings",
        lambda *args, **kwargs: MOCK_ANCHORE_FINDINGS,
    )
    monkeypatch.setattr(
        AnchoreReportParser, "write_csv_from_dict_list", lambda *args, **kwargs: None
    )
    len_findings = pipeline_csv_gen.generate_anchore_cve_report(
        report_path=Path("report"),
        csv_output_dir=Path("csv_out"),
        justifications={("456", None, None): "t_just"},
    )
    assert len_findings == 2


def test_generate_anchore_compliance_report(monkeypatch) -> None:
    monkeypatch.setattr(Path, "open", mock_open())

    log.info("Test successful anchore compliance report generation")
    monkeypatch.setattr(json, "load", lambda *args, **kwargs: MOCK_ANCHORE_REPORT)
    monkeypatch.setattr(
        ReportParser, "write_csv_from_dict_list", lambda *args, **kwargs: None
    )
    stop_count, image_id = pipeline_csv_gen.generate_anchore_compliance_report(
        report_path=Path("report"),
        csv_output_dir=Path("csv_out"),
        justifications={("456", None, None): "t_just"},
    )
    assert stop_count == 1
    assert image_id == "t_sha"


def test_generate_twistlock_cve_report(monkeypatch, caplog) -> None:
    log.info("Test successful twistlock cve report generation")
    monkeypatch.setattr(Path, "open", mock_open())
    monkeypatch.setattr(
        ReportParser, "write_csv_from_dict_list", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(json, "load", lambda *args, **kwargs: MOCK_TWISTLOCK_CVE_REPORT)
    cve_len = pipeline_csv_gen.generate_twistlock_cve_report(
        report_path=Path("report"),
        csv_output_dir=Path("csv_out"),
        justifications={("t_id", "t_pkg_name-t_pkg_ver", None): "t_just"},
    )
    assert cve_len == 1

    log.info("Test key error")
    # Remove severity key to introduce key error
    MOCK_TWISTLOCK_CVE_REPORT["results"][0]["vulnerabilities"][0].pop("severity")
    monkeypatch.setattr(json, "load", lambda *args, **kwargs: MOCK_TWISTLOCK_CVE_REPORT)
    with pytest.raises(SystemExit):
        cve_len = pipeline_csv_gen.generate_twistlock_cve_report(
            report_path=Path("report"),
            csv_output_dir=Path("csv_out"),
            justifications={},
        )
    assert "Missing key." in caplog.text

    log.info("Test no cves")
    monkeypatch.setattr(json, "load", lambda *args, **kwargs: {"results": [{}]})
    cve_len = pipeline_csv_gen.generate_twistlock_cve_report(
        report_path=Path("report"), csv_output_dir=Path("csv_out"), justifications={}
    )
    assert cve_len == 0


def test_generate_oscap_compliance_report(monkeypatch, caplog) -> None:
    log.info("Test successful oscap compliance report generated")
    monkeypatch.setattr(Path, "open", mock_open())
    monkeypatch.setattr(
        OscapReportParser, "get_findings", lambda *args, **kwargs: MOCK_OSCAP_FINDINGS
    )
    mock_writer = MockWriter()
    monkeypatch.setattr(csv, "writer", lambda *args, **kwargs: mock_writer)
    fail_count, nc_count = pipeline_csv_gen.generate_oscap_compliance_report(
        report_path=Path("report"), csv_output_dir=Path("csv_out"), justifications={}
    )
    assert fail_count == 1
    assert nc_count == 1

    log.info("Test csv writerow exception")
    monkeypatch.setattr(
        MockWriter, "writerow", lambda *args, **kwargs: raise_(Exception)
    )
    mock_writer = MockWriter()
    monkeypatch.setattr(csv, "writer", lambda *args, **kwargs: mock_writer)
    with pytest.raises(Exception) as e:
        fail_count, nc_count = pipeline_csv_gen.generate_oscap_compliance_report(
            report_path=Path("report"),
            csv_output_dir=Path("csv_out"),
            justifications={},
        )
    assert "Problem writing line" in caplog.text


def test_generate_blank_oscap_report(monkeypatch) -> None:
    log.info("Test generate blank oscap report")
    monkeypatch.setattr(Path, "open", mock_open())
    mock_writer = MockWriter()
    monkeypatch.setattr(csv, "writer", lambda *args, **kwargs: mock_writer)
    pipeline_csv_gen.generate_blank_oscap_report(Path("test"))
    assert mock_writer.rows == [
        [
            "OpenSCAP Scan Skipped Due to Base Image Used",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
    ]
