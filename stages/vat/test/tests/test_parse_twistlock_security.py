import pytest
import os
import sys
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging
import logging.handlers
import vat_import

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


def test_parse_twistlock_security_exception():

    csv_dir = Path("./stages/vat/test/test_data")
    tl_path = csv_dir.joinpath("tl_not_exist.csv")
    with pytest.raises(Exception):
        assert vat_import.parse_twistlock_security(tl_path)


def test_parse_twistlock_security():

    csv_dir = Path("./stages/vat/test/test_data")
    tl_path = csv_dir.joinpath("tl.csv")
    vat_import.remove_lame_header_row(tl_path)
    rslt = vat_import.parse_twistlock_security(tl_path)

    assert rslt.shape[0] == 6, "Row count = 7"

    assert rslt.at[0, "finding"] == "CVE-2016-1000031", "finding"
    assert (
        rslt.at[0, "description"]
        == "Apache Commons FileUpload before 1.3.3 DiskFileItem File Manipulation Remote Code Execution"
    ), "description"
    assert (
        rslt.at[0, "package"] == "commons-fileupload_commons-fileupload-1.3.1-jenkins-2"
    ), "package"
    assert rslt.at[0, "score"] == 9.8, "score"
    assert rslt.at[0, "severity"] == "critical", "severity(0)"
    assert rslt.at[1, "severity"] == "high", "severity(1)"
    assert rslt.at[4, "severity"] == "medium", "severity(4)"
