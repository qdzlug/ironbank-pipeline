import os
import sys
import pathlib
import pytest


sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from utils.testing import raise_  # noqa E402


mock_path = pathlib.Path(
    pathlib.Path(__file__).absolute().parent.parent.parent, "mocks"
)

# TODO