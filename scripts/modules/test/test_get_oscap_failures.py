import pytest
import os
import sys
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from get_oscap_failures import (
    _format_reference,
    generate_oscap_jobs,
    get_oval_findings,
    get_redhat_oval_definitions,
)  # noqa E402


def test_format_reference():
    pass


def test_generate_oscap_jobs():
    pass


def test_get_oval_findings():
    pass


def test_get_redhat_oval_definitions():
    pass
