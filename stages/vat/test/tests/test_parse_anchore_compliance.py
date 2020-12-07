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
os.environ["LOGLEVEL"] = "DEBUG"
vat_import.logs.setLevel(logging.DEBUG)
vat_import.logs.addHandler(console)
vat_import.logs.addHandler(handler)


def test_parse_anchore_compliance_exception():

    csv_dir = Path("./stages/vat/test/test_data")
    ac_path = csv_dir.joinpath("anchore_gates_not_exist.csv")
    with pytest.raises(Exception):
        assert vat_import.parse_anchore_compliance(ac_path)


def test_parse_anchore_compliance():

    csv_dir = Path("./stages/vat/test/test_data")
    ac_path = csv_dir.joinpath("anchore_gates.csv")
    vat_import.remove_lame_header_row(ac_path)
    rslt = vat_import.parse_anchore_compliance(ac_path)

    assert rslt.shape[0] == 6, "Row count = 6"

    assert rslt.at[1, "finding"] == "639f6f1177735759703e928c14714a59", "finding"
    assert (
        rslt.at[1, "description"]
        == "SUID or SGID found set on file /usr/bin/chage. Mode: 0o104755\n Gate: files\n Trigger: suid_or_guid_set\n Policy ID: DoDFileChecks"
    )
    assert rslt.at[1, "severity"] == "ga_go", "severity: go"
    assert rslt.at[2, "severity"] == "ga_go", "severity: go"
    assert rslt.at[3, "severity"] == "ga_stop", "severity: stop"
    assert rslt.at[4, "severity"] == "ga_go", "severity: go"
    assert rslt.at[5, "severity"] == "ga_warn", "severity: warn"
    assert rslt.at[6, "severity"] == "ga_stop", "severity: go"
