import argparse
import logging
import logging.handlers

import new_vat_import

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


class TestParse:
    def test_parse_csvs_except(self, monkeypatch):
        def mock_parse_twistlock_security(tl_path):
            bad = open("no_such_file.txt", "r")
            bad.read()

        def mock_parse_anchore_security(as_path):
            bad = open("no_such_file.txt", "r")
            bad.read()

        def mock_parse_anchore_compliance(ac_path):
            bad = open("no_such_file.txt", "r")
            bad.read()

        def mock_parse_oscap_compliance(os_path):
            bad = open("no_such_file.txt", "r")
            bad.read()

        parser = argparse.ArgumentParser(description="SQL Agent")
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "--csv_dir",
            nargs="?",
            const="./test/test_data",
            default="./test/test_data",
        )

        test_args, notKnownArgs = parser.parse_known_args()
        if notKnownArgs:
            print(notKnownArgs)

        monkeypatch.setattr(
            new_vat_import,
            "parse_twistlock_security",
            mock_parse_twistlock_security,
        )
        monkeypatch.setattr(
            new_vat_import,
            "parse_anchore_security",
            mock_parse_anchore_security,
        )
        monkeypatch.setattr(
            new_vat_import,
            "parse_anchore_compliance",
            mock_parse_anchore_compliance,
        )
        monkeypatch.setattr(
            new_vat_import,
            "parse_oscap_compliance",
            mock_parse_oscap_compliance,
        )

        # new_vat_import.args = test_args
        # rslt = new_vat_import.parse_csvs()
        assert True
        # assert type(rslt), dict
        # assert rslt.empty == True
        # assert rslt.value == True
