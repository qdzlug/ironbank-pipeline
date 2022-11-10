#!/usr/bin/env python3

import pytest
from pathlib import Path
from dataclasses import dataclass
from unittest import mock
from unittest.mock import patch, mock_open
from ironbank.pipeline.utils import logger
from ironbank.pipeline.test.mocks.mock_classes import MockPath, MockOpen
from ironbank.pipeline.scan_report_parsers.report_parser import ReportParser, AbstractVuln

log = logger.setup("test_report_parser")


@dataclass
class MockAbstractVuln(AbstractVuln):
    cve: str = None
    package: str = None
    package_path: str = None

def test_get_justification():
    tracked_vuln1 = MockAbstractVuln(cve="001", package="testPkg", package_path="testPkgPth")
    tracked_vuln2 = MockAbstractVuln(cve="002", package="testPkg", package_path="pkgdb")
    untracked_vuln = MockAbstractVuln(cve="003", package="testPkg", package_path="testPkgPth")
    vuln1_id = ("001", "testPkg", "testPkgPth")
    vuln2_id = ("002", "testPkg", None)
    justifications = {
        vuln1_id: "testJustification1",
        vuln2_id: "testJustification2",
    }

    log.info("Test get justification success")
    just = ReportParser.get_justification(tracked_vuln1, justifications)
    assert just == "testJustification1"

    log.info("Test get justification success with package_path=pkgdb")
    just = ReportParser.get_justification(tracked_vuln2, justifications)
    assert just == "testJustification2"

    log.info("Test get justification return None")
    just = ReportParser.get_justification(untracked_vuln, justifications)
    assert just == None



@pytest.mark.only
@patch('csv.writer')
def test_write_csv_from_dict_list(monkeypatch, csv_writer_mock):

    test_dict_list = [
        {
            "id": "id1",
            "desc": "description1",
        },
        {
            "id": "id2",
            "desc": "description2",           
        }
    ]
    test_fieldnames = [
        "id",
        "desc",
    ]
    mopen = mock_open()
    monkeypatch.setattr(Path, "open", mopen)
    ReportParser.write_csv_from_dict_list(csv_dir="csv_dir", dict_list=test_dict_list, fieldnames=test_fieldnames, filename="test.csv")
    assert mopen.assert_called_with(test_dict_list)

    
    

