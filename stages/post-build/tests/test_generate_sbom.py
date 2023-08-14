#!/usr/bin/env python3
import sys
from pathlib import Path
from common.utils import logger

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import generate_sbom
from ironbank_py39_modules.scanner_api_handlers.anchore import Anchore  # noqa: E402

log = logger.setup("test_generate_sbom")


def test_main(monkeypatch, caplog):
    monkeypatch.setattr(Anchore, "generate_sbom", lambda *args, **kwargs: None)
    monkeypatch.setenv("ANCHORE_URL", "mock_ANCHORE_URL")
    monkeypatch.setenv("ANCHORE_USERNAME", "mock_ANCHORE_USERNAME")
    monkeypatch.setenv("ANCHORE_VERIFY", "mock_ANCHORE_VERIFY")
    monkeypatch.setenv("SBOM_DIR", "mock_SBOM_DIR")
    monkeypatch.setenv("IMAGE_FULLTAG", "mock_IMAGE_FULLTAG")

    generate_sbom.main()
    assert "Generated SBOMs" in caplog.text
