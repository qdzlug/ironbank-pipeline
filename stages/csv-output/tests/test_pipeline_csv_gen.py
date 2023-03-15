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


MOCK_OSCAP_FINDINGS: list[OscapComplianceFinding] = [
    OscapComplianceFinding(identifier="test1", severity="test1", result="fail"),
    OscapComplianceFinding(identifier="test2", severity="test2", result="notchecked"),
]

MOCK_GOOD_TWISTLOCK_CVE_FINDINGS: dict = {
    "results": [
        {
            "vulnerabilities": [
                {
                    "id": "t_id",
                    "status": "t_status",
                    "cvss": 10,
                    "vector": "t_vector",
                    "description": "t_desc",
                    "severity": "t_sev",
                    "packageName": "t_pkg_name",
                    "packageVersion": "t_pkg_ver",
                    "link": "t_link",
                    "riskFactors": [
                        "t_risk",
                    ],
                    "impactedVersions": ["t_imp_vers"],
                    "publishedDate": "t_pub_date",
                    "discoveredDate": "t_disc_date",
                    "layerTime": "t_layer_time",
                }
            ]
        }
    ]
}

MOCK_BAD_TWISTLOCK_CVE_FINDINGS: dict = {
    "results": [
        {
            "vulnerabilities": [
                {
                    "id": "bad_id",
                    "packageName": "bad_packageName",
                    "packageVersion": "bad_packageVersion",
                }
            ]
        }
    ]
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
def test_generate_twistlock_cve_report(monkeypatch, caplog):
    log.info("Test successful report generation")
    monkeypatch.setattr(Path, "open", mock_open())
    monkeypatch.setattr(
        ReportParser, "write_csv_from_dict_list", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        json, "load", lambda *args, **kwargs: MOCK_GOOD_TWISTLOCK_CVE_FINDINGS
    )
    cve_len = pipeline_csv_gen.generate_twistlock_cve_report(
        report_path=Path("report"),
        csv_output_dir=Path("csv_out"),
        justifications={("t_id", "t_pkg_name-t_pkg_ver", None): "t_just"},
    )
    assert cve_len == 1

    log.info("Test key error")
    monkeypatch.setattr(
        json, "load", lambda *args, **kwargs: MOCK_BAD_TWISTLOCK_CVE_FINDINGS
    )
    with pytest.raises(SystemExit):
        cve_len = pipeline_csv_gen.generate_twistlock_cve_report(
            report_path=Path("report"),
            csv_output_dir=Path("csv_out"),
            justifications={},
        )
    assert "Missing key." in caplog.text

    log.info("Test no cves")
    monkeypatch.setattr(
        json, "load", lambda *args, **kwargs: {"results": [{"vulnerabilities": []}]}
    )
    cve_len = pipeline_csv_gen.generate_twistlock_cve_report(
        report_path=Path("report"), csv_output_dir=Path("csv_out"), justifications={}
    )
    assert cve_len == 0


def test_generate_oscap_compliance_report(monkeypatch, caplog):
    log.info("Test successful report generated")
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


def test_generate_blank_oscap_report(monkeypatch):
    log.info("Test generate blank report")
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
