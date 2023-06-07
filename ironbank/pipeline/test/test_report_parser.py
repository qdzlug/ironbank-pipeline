#!/usr/bin/env python3

import csv
from dataclasses import dataclass
from io import TextIOWrapper
from pathlib import Path
from unittest.mock import mock_open

from ironbank.pipeline.scan_report_parsers.report_parser import (
    AbstractFinding,
    ReportParser,
)
from ironbank.pipeline.utils import logger

log = logger.setup("test_report_parser")


@dataclass
class MockAbstractFinding(AbstractFinding):
    cve: str = None
    package: str = None
    package_path: str = None
    identifier: str = None
    severity: str = None


@dataclass
class MockDictWriter:
    file_: TextIOWrapper = None
    fieldnames: list[str] = None
    rows: list[dict] = None

    def writeheader(self):
        pass

    def writerows(self, dict_list: list[dict]):
        self.rows = dict_list


def test_get_justification():
    tracked_vuln1 = MockAbstractFinding(
        identifier="001", package="testPkg", package_path="testPkgPth"
    )
    tracked_vuln2 = MockAbstractFinding(
        identifier="002", package="testPkg", package_path="pkgdb"
    )
    untracked_vuln = MockAbstractFinding(
        identifier="003", package="testPkg", package_path="testPkgPth"
    )
    vuln1_id = ("001", "testPkg", "testPkgPth")
    vuln2_id = ("002", "testPkg", None)
    justifications = {
        vuln1_id: "testJustification1",
        vuln2_id: "testJustification2",
    }

    log.info("Test get justification success")
    just = AbstractFinding.get_justification(tracked_vuln1, justifications)
    assert just == "testJustification1"

    log.info("Test get justification success with package_path=pkgdb")
    just = AbstractFinding.get_justification(tracked_vuln2, justifications)
    assert just == "testJustification2"

    log.info("Test get justification return None")
    just = AbstractFinding.get_justification(untracked_vuln, justifications)
    assert just == ""


def test_get_dict_from_fieldnames():
    log.info("Test dict is returned with expected fieldnames")
    finding = AbstractFinding(
        identifier="testID", severity="testSev", scan_source="testSrc"
    )
    test_dict = finding.get_dict_from_fieldnames(["finding", "packagePath"])
    assert test_dict["finding"] == "testID"
    assert test_dict["packagePath"] == ""


def test_write_csv_from_dict_list(monkeypatch):
    test_dict_list = [
        {
            "id": "id1",
            "desc": "description1",
        },
        {
            "id": "id2",
            "desc": "description2",
        },
    ]
    test_fieldnames = [
        "id",
        "desc",
    ]
    monkeypatch.setattr(Path, "open", mock_open())
    mock_dict_writer = MockDictWriter()
    monkeypatch.setattr(csv, "DictWriter", lambda *args, **kwargs: mock_dict_writer)

    log.info("Test successful initialization and function calls")
    ReportParser.write_csv_from_dict_list(
        csv_dir="csv_dir",
        dict_list=test_dict_list,
        fieldnames=test_fieldnames,
        filename="test.csv",
    )
    assert mock_dict_writer.rows == test_dict_list


def test_dedupe_findings_by_attr():
    log.info("Test no duplicates")
    findings = [
        AbstractFinding(identifier="1", severity="1"),
        AbstractFinding(identifier="2", severity="2"),
    ]
    deduped_findings = ReportParser.dedupe_findings_by_attr(findings, "identifier")
    assert len(deduped_findings) == 2

    log.info("Test remove duplicates")
    findings = [
        AbstractFinding(identifier="1", severity="1"),
        AbstractFinding(identifier="1", severity="2"),
    ]
    deduped_findings = ReportParser.dedupe_findings_by_attr(findings, "identifier")
    assert len(deduped_findings) == 1
    assert deduped_findings[0].identifier == "1"
