import pytest
import os
import sys
from pathlib import Path

import logging
import logging.handlers

import new_vat_import

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


new_vat_import.logs = logging.getLogger("Tests")
formatter = logging.Formatter("%(levelname)-8s %(message)s")
console = logging.StreamHandler()
console.setFormatter(formatter)
LOG_FILE = "test_logging.out"
handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=(1048576 * 5), backupCount=3
)
handler.setFormatter(formatter)
new_vat_import.logs.setLevel(logging.ERROR)
new_vat_import.logs.addHandler(console)
new_vat_import.logs.addHandler(handler)


def test_parse_anchore_security_exception():

    csv_dir = Path("./test/test_data")
    as_path = csv_dir.joinpath("anchore_not_exist.csv")
    with pytest.raises(Exception):
        assert new_vat_import.parse_anchore_security(as_path)


def test_parse_anchore_security():

    csv_dir = Path("./test/test_data")
    as_path = csv_dir.joinpath("anchore_security.csv")
    new_vat_import.remove_lame_header_row(as_path)

    rslt = new_vat_import.parse_anchore_security(as_path)
    assert len(rslt) == 7, "Row count = 7"

    assert rslt[0]["finding"] == "CVE-2019-9948", "finding"
    assert (
        rslt[0]["description"]
        == "Python-2.7.5\nhttps://nvd.nist.gov/vuln/detail/CVE-2019-9948"
    ), "description"
    assert rslt[0]["link"] is None, "link"
    assert rslt[0]["package"] == "Python-2.7.5", "package"
    assert (
        rslt[0]["packagePath"] == "/opt/app-root/lib/python3.6/site-packages/pip"
    ), "package"

    assert rslt[0]["severity"] == "critical", "severity"
    assert rslt[1]["severity"] == "medium", "severity"
    assert rslt[3]["severity"] == "high", "severity"
