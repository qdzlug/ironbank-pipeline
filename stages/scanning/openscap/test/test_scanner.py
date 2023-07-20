import pytest
import sys
from pathlib import Path
from envs import Envs
from scanner import Scanner

from mocks import MockImage, MockOpenSCAP

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
from pipeline.utils.exceptions import GenericSubprocessError


class MockScanner(Scanner):
    def _run_subprocess(self) -> None:
        return None


class MockScannerError(Scanner):
    def _run_subprocess(self) -> None:
        raise GenericSubprocessError


def test_scanner_scan(monkeypatch, caplog):  # type: ignore
    monkeypatch.setattr(Envs, "base_image_type", "ubi9-container")
    image = MockImage(MockOpenSCAP())
    scanner = MockScanner(image)

    # should log the command
    scanner.scan()
    assert "Command" in caplog.text, f"Logging failed. Log: {caplog.text}"
    # TODO: add these tests again once the pylint plugin is updated
    # assert isinstance(scanner.command, list)
    # assert len(scanner.command) > 0

    # should log success
    assert "success" in caplog.text, f"Logging failed. Log: {caplog.text}"
    caplog.clear()

    # should raise an error and log the error
    scanner = MockScannerError(image)
    with pytest.raises(GenericSubprocessError):
        scanner.scan()
    assert "Error" in caplog.text, f"Logging failed. Log: {caplog.text}"
    caplog.clear()
