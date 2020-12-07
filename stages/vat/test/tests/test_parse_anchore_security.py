import pytest
import os
import sys
from pathlib import Path

import logging
import logging.handlers

import vat_import

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


vat_import.logs = logging.getLogger("Tests")
formatter = logging.Formatter("%(levelname)-8s %(message)s")
console = logging.StreamHandler()
console.setFormatter(formatter)
LOG_FILE = "test_logging.out"
handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=(1048576 * 5), backupCount=3
)
handler.setFormatter(formatter)
vat_import.logs.setLevel(logging.DEBUG)
vat_import.logs.addHandler(console)
vat_import.logs.addHandler(handler)


def test_parse_anchore_security_exception():

    csv_dir = Path("./stages/vat/test/test_data")
    as_path = csv_dir.joinpath("anchore_not_exist.csv")
    with pytest.raises(Exception):
        assert vat_import.parse_anchore_security(as_path)


def test_parse_anchore_security():

    csv_dir = Path("./stages/vat/test/test_data")
    as_path = csv_dir.joinpath("anchore_security.csv")
    vat_import.remove_lame_header_row(as_path)

    rslt = vat_import.parse_anchore_security(as_path)

    assert rslt.shape[0] == 7, "Row count = 7"

    assert rslt.at[0, "finding"] == "CVE-2019-9948", "finding"
    assert (
        rslt.at[0, "description"]
        == "Python-2.7.5\nhttps://nvd.nist.gov/vuln/detail/CVE-2019-9948"
    ), "description"
    assert rslt.at[0, "link"] is None, "link"
    assert rslt.at[0, "package"] == "Python-2.7.5", "package"
    assert (
        rslt.at[0, "package_path"] == "/opt/app-root/lib/python3.6/site-packages/pip"
    ), "package"

    assert rslt.at[0, "severity"] == "Critical", "severity"
    assert rslt.at[1, "severity"] == "Medium", "severity"
    assert rslt.at[3, "severity"] == "High", "severity"
