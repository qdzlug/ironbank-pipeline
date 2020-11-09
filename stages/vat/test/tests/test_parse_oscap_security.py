import os
import sys
import argparse
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

parser = argparse.ArgumentParser(description="Report Parser")
parser.add_argument(
    "--link",
    nargs="?",
    const="https://dsop-pipeline-artifacts.s3-us-gov-west-1.amazonaws.com",
    default="https://dsop-pipeline-artifacts.s3-us-gov-west-1.amazonaws.com",
)


def test_parse_oscap_security():

    csv_dir = Path("./stages/vat/test/test_data")
    ov_path = csv_dir.joinpath("oval.csv")
    test_args, notKnownArgs = parser.parse_known_args()
    if notKnownArgs:
        print(notKnownArgs)
    vat_import.args = test_args

    vat_import.remove_lame_header_row(ov_path)
    rslt = vat_import.parse_oscap_security(ov_path)

    assert rslt.shape[0] == 14, "Row count = 14"

    print("rslt pkg")
    print(rslt.at[0, "package"])

    assert rslt.at[0, "finding"] == "CVE-2019-15688", "finding"
    assert rslt.at[0, "description"] == "", "description"
    assert rslt.at[0, "package"] == "libvncserver", "package"
    assert rslt.at[0, "severity"] == "high", "severity(1)"
    assert rslt.at[1, "severity"] == "low", "severity(3)"
    assert rslt.at[2, "severity"] == "critical", "severity(6)"
    assert rslt.at[3, "severity"] == "medium", "severity(7)"
