#!/usr/bin/env python3

import csv
import json
import sys
from dataclasses import dataclass
from io import TextIOWrapper
from pathlib import Path
from typing import Any, Iterable
from unittest.mock import mock_open

import pytest

from ironbank.pipeline.scan_report_parsers.anchore import (
    AnchoreCVEFinding,
    AnchoreReportParser,
)
from ironbank.pipeline.scan_report_parsers.oscap import (
    OscapComplianceFinding,
    OscapReportParser,
)
from ironbank.pipeline.scan_report_parsers.report_parser import ReportParser
from ironbank.pipeline.utils import logger

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
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
    stored_rows: list[Iterable[Any]] = None

    def writerow(self, row: Iterable[Any]):
        if not self.stored_rows:
            self.stored_rows = []
        self.stored_rows.append(row)

    def writerows(self, rows: Iterable[Iterable]):
        if not self.stored_rows:
            self.stored_rows = []
        for row in rows:
            self.stored_rows.append(row)


def test_main(monkeypatch, caplog, raise_) -> None:
    monkeypatch.setenv("ANCHORE_SCANS", "1")
    monkeypatch.setenv("TWISTLOCK_SCANS", "2")
    monkeypatch.setenv("OSCAP_SCANS", "3")
    monkeypatch.setenv("CSV_REPORT", "4")
    monkeypatch.setenv("ARTIFACT_STORAGE", "4")
    monkeypatch.setattr(Path, "open", mock_open())
    monkeypatch.setattr(Path, "mkdir", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        pipeline_csv_gen,
        "sort_justifications",
        lambda *args, **kwargs: ({"1": 1}, {"1": 1}, {"1": 1}, {"1": 1}),
    )
    monkeypatch.setattr(
        pipeline_csv_gen,
        "generate_oscap_compliance_report",
        lambda *args, **kwargs: (1, 1),
    )
    monkeypatch.setattr(
        pipeline_csv_gen, "generate_blank_oscap_report", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        pipeline_csv_gen, "generate_twistlock_cve_report", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        pipeline_csv_gen, "generate_anchore_cve_report", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        pipeline_csv_gen,
        "generate_anchore_compliance_report",
        lambda *args, **kwargs: (1, "1"),
    )
    monkeypatch.setattr(
        pipeline_csv_gen, "generate_summary_report", lambda *args, **kwargs: None
    )
    log.info("Test exception thrown opening vat findings file")
    monkeypatch.setattr(json, "load", lambda *args, **kwargs: raise_(Exception))
    with pytest.raises(SystemExit):
        pipeline_csv_gen.main()
    assert "Error reading findings file." in caplog.text

    log.info("Test sequence to generate blank oscap report")
    monkeypatch.setattr(json, "load", lambda *args, **kwargs: None)
    monkeypatch.setenv("SKIP_OPENSCAP", "")
    pipeline_csv_gen.main()

    log.info("Test sequence to generate oscap compliance report")
    monkeypatch.delenv("SKIP_OPENSCAP")
    pipeline_csv_gen.main()


def test_generate_summary_report(monkeypatch) -> None:
    log.info("Test successful summary report generated")
    monkeypatch.setattr(Path, "open", mock_open())
    mock_writer = MockWriter()
    monkeypatch.setattr(csv, "writer", lambda *args, **kwargs: mock_writer)
    pipeline_csv_gen.generate_summary_report(
        oscap_comp_fail_count=1,
        oscap_comp_not_checked_count=1,
        twistlock_cve_fail_count=1,
        anchore_cve_fail_count=1,
        anchore_comp_fail_count=1,
        image_id="t_id",
        csv_output_dir=Path("csv_out"),
    )
    assert (
        "Scans performed on container layer sha256: t_id,,,"
        in mock_writer.stored_rows[-1]
    )


def test_generate_anchore_cve_report(monkeypatch) -> None:
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


def test_generate_oscap_compliance_report(monkeypatch, caplog, raise_) -> None:
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
    with pytest.raises(Exception):
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
    assert mock_writer.stored_rows == [
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
