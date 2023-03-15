#!/usr/bin/env python3

from io import TextIOWrapper
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

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pipeline_csv_gen  # noqa E402

log = logger.setup("test_pipeline_csv_gen")


OSCAP_FINDINGS: list[OscapComplianceFinding] = [
    OscapComplianceFinding(identifier="test1", severity="test1", result="fail"),
    OscapComplianceFinding(identifier="test2", severity="test2", result="notchecked"),
]


@dataclass
class MockWriter:
    file_: TextIOWrapper = None
    fieldnames: list[str] = None
    rows: list[Iterable[Any]] = None

    def writerow(self, row: Iterable[Any]):
        if not self.rows:
            self.rows = []
        self.rows.append(row)


def test_generate_oscap_compliance_report(monkeypatch, caplog):
    log.info("Test successful report generated")
    monkeypatch.setattr(Path, "open", mock_open())
    monkeypatch.setattr(
        OscapReportParser, "get_findings", lambda *args, **kwargs: OSCAP_FINDINGS
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
