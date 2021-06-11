import os
import sys
import argparse
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

parser = argparse.ArgumentParser(description="Report Parser")
parser.add_argument(
    "--comp_link",
    nargs="?",
    const="https://repo1.dso.mil/dsop/opensource/pipeline-test-project/csvs",
    default="https://repo1.dso.mil/dsop/opensource/pipeline-test-project/csvs",
)

parser.add_argument("--debug", nargs="?", const=True, default=True)


def test_parse_oscap_compliance():

    csv_dir = Path("./test/test_data")
    os_path = csv_dir.joinpath("oscap.csv")

    test_args, notKnownArgs = parser.parse_known_args()
    new_vat_import.args = test_args

    new_vat_import.remove_lame_header_row(os_path)
    rslt = new_vat_import.parse_oscap_compliance(os_path)

    assert len(rslt) == 22, "Row count = 22"

    print("*********************", rslt)
    assert rslt[0]["finding"] == "CCE-82880-6", "finding"
    assert (
        rslt[0]["description"] == "Configure session renegotiation for SSH client"
    ), "description"
    assert rslt[0]["severity"] == "medium", "severity(131)"
    # assert rslt[155]["severity"] == "low", "severity(155)"
    assert rslt[len(rslt) - 1]["severity"] == "medium", "severity(187)"
