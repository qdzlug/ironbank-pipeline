import pytest
import sys
import os
import pathlib

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from mocks.mock_classes import MockProject  # noqa E402

def test_validate_files_exist(monkeypatch):
    mock_project = MockProject()
    monkeypatch.setattr(pathlib.Path, 'exists', lambda self: False)
    mock_project.validate_files_exist()

    with pytest.raises(AssertionError) as ae:
        monkeypatch.setattr(pathlib.Path, 'exists', lambda self: True)
        mock_project.validate_files_exist()