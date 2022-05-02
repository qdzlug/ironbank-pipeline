import pytest
import os
import sys
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from get_oscap_failures import _format_reference  # noqa E402
from get_oscap_failures import generate_oscap_jobs  # noqa E402
from get_oscap_failures import get_oval_findings  # noqa E402
from get_oscap_failures import get_redhat_oval_definitions  # noqa E402


def test_format_reference():
    pass


def test_generate_oscap_jobs():
    pass


def test_get_oval_findings():
    pass


def test_get_redhat_oval_definitions():
    pass
