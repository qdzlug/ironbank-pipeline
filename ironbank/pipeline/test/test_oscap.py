#!/usr/bin/env python3


from dataclasses import dataclass
from xml.etree import ElementTree
from ironbank.pipeline.scan_report_parsers.oscap import OscapReportParser
from ironbank.pipeline.test.mocks.mock_classes import MockPath
import pytest

from pathlib import Path
from ironbank.pipeline.utils import logger
log = logger.setup("test_oscap")

@dataclass 
class MockRuleInfo:
    
    


@pytest.mark.only
def test_oscap_report_parser_get_findings(monkeypatch, caplog):
    oscap_report_parser = OscapReportParser()
    monkeypatch.setattr(ElementTree, "parse", lambda report_path: report_path)
    oscap_report_parser.get_findings(MockPath("mockedpath"))
   



