#!/usr/bin/env python3
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from common.utils import logger

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import generate_sbom

log = logger.setup("test generate_sbom.main")


def test_main(monkeypatch, caplog):
    monkeypatch.setenv("ANCHORE_URL", "mock_ANCHORE_URL")
    monkeypatch.setenv("ANCHORE_USERNAME", "mock_ANCHORE_USERNAME")
    monkeypatch.setenv("ANCHORE_VERIFY", True)
    monkeypatch.setenv("SBOM_DIR", "mock_SBOM_DIR")
    monkeypatch.setenv("IMAGE_FULLTAG", "mock_IMAGE_FULLTAG")

    with patch("generate_sbom.Anchore", new=MagicMock()) as MockedAnchore:
        mock_anchore_instance = MockedAnchore.return_value
        generate_sbom.main()
        MockedAnchore.assert_called_with(
            url="mock_ANCHORE_URL",
            username="mock_ANCHORE_USERNAME",
            password="",
            verify="True",
        )

        mock_anchore_instance.generate_sbom.assert_has_calls(
            [
                call("mock_IMAGE_FULLTAG", "mock_SBOM_DIR", "cyclonedx-json", "json"),
                call("mock_IMAGE_FULLTAG", "mock_SBOM_DIR", "spdx-tag-value", "txt"),
                call("mock_IMAGE_FULLTAG", "mock_SBOM_DIR", "spdx-json", "json"),
                call("mock_IMAGE_FULLTAG", "mock_SBOM_DIR", "json", "json", "syft"),
            ]
        )
