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

    assert rslt.shape[0] == 11, "Row count = 11"

    assert rslt.at[0, "finding"] == "CVE-2020-8927", "finding"
    assert (
        rslt.at[1, "description"]
        == "Due to use of a \"dangling\" pointer, libcurl 7.29.0 through 7.71.1 can use the wrong connection when "
           "sending data.\nLink: https://access.redhat.com/security/cve/CVE-2020-8231"
    ), "description"
    assert (
        rslt.at[5, "description"]
        == "none\nLink: https://access.redhat.com/security/cve/CVE-2020-35512"
    ), "description"
    assert rslt.at[0, "link"] == "https://access.redhat.com/security/cve/CVE-2020-8927", "link"
    assert rslt.at[0, "package"] == "brotli-1.0.6-2.el8", "package"
    assert rslt.at[0, "package_path"] is None, "package_path"

    assert rslt.at[0, "severity"] == "Medium", "severity"
    assert rslt.at[1, "severity"] == "Low", "severity"
    assert rslt.at[10, "severity"] == "High", "severity"
