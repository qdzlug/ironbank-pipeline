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
os.environ["LOGLEVEL"] = "DEBUG"
new_vat_import.logs.setLevel(logging.ERROR)
new_vat_import.logs.addHandler(console)
new_vat_import.logs.addHandler(handler)


def test_parse_anchore_compliance_exception():

    csv_dir = Path("./test/test_data")
    ac_path = csv_dir.joinpath("anchore_gates_not_exist.csv")
    with pytest.raises(Exception):
        assert new_vat_import.parse_anchore_compliance(ac_path)


def test_parse_anchore_compliance():

    csv_dir = Path("./test/test_data")
    ac_path = csv_dir.joinpath("anchore_gates.csv")
    rslt = new_vat_import.parse_anchore_compliance(ac_path)
    assert len(rslt) == 6, "Row count = 6"

    assert rslt[0]["finding"] == "639f6f1177735759703e928c14714a59", "finding"
    assert (
        rslt[0]["description"]
        == "SUID or SGID found set on file /usr/bin/chage. Mode: 0o104755\n Gate: files\n Trigger: suid_or_guid_set\n Policy ID: DoDFileChecks"
    )
    assert rslt[0]["severity"] == "ga_go", "severity: go"
    assert rslt[1]["severity"] == "ga_go", "severity: go"
    assert rslt[2]["severity"] == "ga_stop", "severity: stop"
    assert rslt[3]["severity"] == "ga_go", "severity: go"
    assert rslt[4]["severity"] == "ga_warn", "severity: warn"
    assert rslt[5]["severity"] == "ga_stop", "severity: go"
