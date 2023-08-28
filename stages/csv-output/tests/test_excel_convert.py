from dataclasses import dataclass, field
from unittest.mock import MagicMock
import pytest
import sys
from pathlib import Path

sys.path.append(Path(__file__).absolute().parents[1].as_posix())

import excel_convert  # noqa E402


@dataclass
class MockCell:
    value: str


@dataclass
class MockSheet(MagicMock):
    def cell(self, row: int, column: int):
        return MockCell()


@dataclass
class MockWorkbook(MagicMock):
    sheets: list[MockSheet] = field(default_factory=lambda: [])
    sheetnames: list[str] = field(init=False, default_factory=lambda: [])
    sheet_map: dict[MockSheet] = field(init=False, default_factory=lambda: {})

    def __post_init__(self):
        self.sheetnames = [sheet.name for sheet in self.sheets]

    def __get_item__(self, index):
        return


def test__add_sheet_banner():
    # add in mocks and stuff
    mock_workbook = MockWorkbook([MockSheet(), MockSheet()])
    excel_convert._add_sheet_banners(mock_workbook)
