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


def test_parse_twistlock_security_exception():

    csv_dir = Path("./test/test_data")
    tl_path = csv_dir.joinpath("tl_not_exist.csv")
    with pytest.raises(Exception):
        assert new_vat_import.parse_twistlock_security(tl_path)


def test_parse_twistlock_security():

    csv_dir = Path("./test/test_data")
    tl_path = csv_dir.joinpath("tl.csv")
    rslt = new_vat_import.parse_twistlock_security(tl_path)

    assert len(rslt) == 6, "Row count = 6"

    assert rslt[0]["finding"] == "CVE-2016-1000031", "finding"
    assert (
        rslt[0]["description"]
        == "Apache Commons FileUpload before 1.3.3 DiskFileItem File Manipulation Remote Code Execution"
    ), "description"
    assert (
        rslt[0]["package"] == "commons-fileupload_commons-fileupload-1.3.1-jenkins-2"
    ), "package"
    assert rslt[0]["score"] == 9.8, "score"
    assert rslt[0]["severity"] == "critical", "severity(0)"
    assert rslt[1]["severity"] == "important", "severity(1)"
    assert rslt[4]["severity"] == "moderate", "severity(4)"
