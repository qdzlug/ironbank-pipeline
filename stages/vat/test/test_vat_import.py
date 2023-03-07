import shutil
import sys

from pathlib import Path
from unittest.mock import patch, MagicMock
from ironbank.pipeline.container_tools.cosign import Cosign

from ironbank.pipeline.utils import logger
from ironbank.pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
    MockImage,
    MockPath,
    MockTempDirectory,
)

log = logger.setup("test_vat_import")

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import vat_import  # noqa E402


@patch("vat_import.Path", new=MockPath)
@patch("vat_import.Image", new=MockImage)
@patch("tempfile.TemporaryDirectory", new=MockTempDirectory)
def test_get_parent_vat_response(monkeypatch):
    monkeypatch.setenv("REGISTRY_BASE_IMAGE_URL", "mock_registry.dso.mil")
    monkeypatch.setenv("DOCKER_AUTH_FILE_PULL", "ZXhhbXBsZQ==")
    monkeypatch.setattr(shutil, "move", lambda from_, to_: None)
    mock_hardening_manifest = MockHardeningManifest(".")
    with patch("vat_import.Cosign", new=MagicMock(spec=Cosign)) as mock_cosign:
        vat_import.get_parent_vat_response(".", mock_hardening_manifest)
        mock_cosign.download.assert_called_once()
