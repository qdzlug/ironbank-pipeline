import pytest
import os
import sys
import argparse
from pathlib import Path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging
import logging.handlers
import vat_import

vat_import.logs = logging.getLogger("Tests")
formatter = logging.Formatter('%(levelname)-8s %(message)s')
console = logging.StreamHandler()
console.setFormatter(formatter)
LOG_FILE = 'test_logging.out'
handler = logging.handlers.RotatingFileHandler(
              LOG_FILE, maxBytes=(1048576*5), backupCount=3)
handler.setFormatter(formatter)
vat_import.logs.setLevel(logging.DEBUG)
vat_import.logs.addHandler(console)
vat_import.logs.addHandler(handler)

parser = argparse.ArgumentParser(description='Report Parser')
parser.add_argument('--link', nargs='?',
                    const='https://dsop-pipeline-artifacts.s3-us-gov-west-1.amazonaws.com',
                    default='https://dsop-pipeline-artifacts.s3-us-gov-west-1.amazonaws.com')
parser.add_argument('--debug', nargs='?',
                    const=True,
                    default=True)


def test_parse_oscap_compliance():

     csv_dir = Path("./stages/vat/test/test_data")
     os_path = csv_dir.joinpath('oscap.csv')
     os_new_path = csv_dir.joinpath('oscap_fails.csv')

     test_args, notKnownArgs = parser.parse_known_args()
     vat_import.args = test_args

     vat_import.remove_lame_header_row(os_path)
     rslt = vat_import.parse_oscap_compliance(os_path)

     assert rslt.shape[0] == 21, "Row count = 21"

     print("rslt")
     print(rslt.at[131,'description'])

     assert rslt.at[131,'finding'] == 'OL07-00-020320', "finding"
     assert rslt.at[131,'description'] == 'Ensure All Files Are Owned by a User', "description"
     assert rslt.at[131,'severity'] == "medium", "severity(131)"
     assert rslt.at[155,'severity'] == "low", "severity(155)"
     assert rslt.at[187,'severity'] == "high", "severity(187)"

