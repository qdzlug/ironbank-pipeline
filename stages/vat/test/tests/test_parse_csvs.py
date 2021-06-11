import pytest
import argparse
import logging
import logging.handlers

import new_vat_import
import unittest

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


class ParseCsvsTestCase(unittest.TestCase):
    def test_parse_csvs_exception(self):

        parser = argparse.ArgumentParser(description="SQL Agent")
        parser = argparse.ArgumentParser()
        parser.add_argument("--csv_dir", nargs="?", const="./test", default="./test")
        parser.add_argument(
            "--sec_link",
            nargs="?",
            const="https://repo1.dso.mil/dsop/opensource/pipeline-test-project/csvs",
            default="https://repo1.dso.mil/dsop/opensource/pipeline-test-project/csvs",
        )
        parser.add_argument(
            "--comp_link",
            nargs="?",
            const="https://repo1.dso.mil/dsop/opensource/pipeline-test-project/csvs",
            default="https://repo1.dso.mil/dsop/opensource/pipeline-test-project/csvs",
        )
        parser.add_argument(
            "--repo_link",
            nargs="?",
            const="https://repo1.dso.mil/dsop/opensource/pipeline-test-project",
            default="https://repo1.dso.mil/dsop/opensource/pipeline-test-project",
        )
        parser.add_argument(
            "--digest",
            nargs="?",
            const="abcdefghijklm1nopqstuvwxyz123456789123456789abcdefghijklmnopqrst",
            default="abcdefghijklm1nopqstuvwxyz123456789123456789abcdefghijklmnopqrst",
        )
        parser.add_argument(
            "--commit_hash",
            nargs="?",
            const="f65d19452198ac1d55045756f2fce6c6b91b1d15",
            default="f65d19452198ac1d55045756f2fce6c6b91b1d15",
        )
        test_args, notKnownArgs = parser.parse_known_args()
        if notKnownArgs:
            print(notKnownArgs)

        new_vat_import.args = test_args
        with pytest.raises(Exception):
            assert new_vat_import.parse_csvs()

    def test_parse_csvs(self):

        parser = argparse.ArgumentParser(description="SQL Agent")
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--container",
            nargs="?",
            const="VENDOR/PRODUCT/CONTAINER",
            default="VENDOR/PRODUCT/CONTAINER",
        )
        parser.add_argument(
            "--version",
            nargs="?",
            const="0.0.1",
            default="0.0.1",
        )
        parser.add_argument(
            "--parent",
            nargs="?",
            const="VENDOR/PRODUCT/PARENT",
            default="VENDOR/PRODUCT/PARENT",
        )
        parser.add_argument(
            "--parent_version",
            nargs="?",
            const="0.0.0",
            default="0.0.0",
        )
        parser.add_argument(
            "--job_id",
            nargs="?",
            const="0",
            default="0",
        )
        parser.add_argument(
            "--scan_date",
            nargs="?",
            const="2021-01-01",
            default="2021-01-01",
        )
        parser.add_argument(
            "--csv_dir",
            nargs="?",
            const="./test/test_data",
            default="./test/test_data",
        )
        parser.add_argument(
            "--sec_link",
            nargs="?",
            const="https://repo1.dso.mil/dsop/opensource/pipeline-test-project/csvs",
            default="https://repo1.dso.mil/dsop/opensource/pipeline-test-project/csvs",
        )
        parser.add_argument(
            "--comp_link",
            nargs="?",
            const="https://repo1.dso.mil/dsop/opensource/pipeline-test-project/csvs",
            default="https://repo1.dso.mil/dsop/opensource/pipeline-test-project/csvs",
        )
        parser.add_argument(
            "--repo_link",
            nargs="?",
            const="https://repo1.dso.mil/dsop/opensource/pipeline-test-project",
            default="https://repo1.dso.mil/dsop/opensource/pipeline-test-project",
        )
        parser.add_argument(
            "--digest",
            nargs="?",
            const="abcdefghijklm1nopqstuvwxyz123456789123456789abcdefghijklmnopqrst",
            default="abcdefghijklm1nopqstuvwxyz123456789123456789abcdefghijklmnopqrst",
        )
        parser.add_argument(
            "--commit_hash",
            nargs="?",
            const="f65d19452198ac1d55045756f2fce6c6b91b1d15",
            default="f65d19452198ac1d55045756f2fce6c6b91b1d15",
        )
        test_args, notKnownArgs = parser.parse_known_args()
        if notKnownArgs:
            print(notKnownArgs)

        new_vat_import.args = test_args
        rslt = new_vat_import.parse_csvs()
        assert type(rslt), dict

        # twistlock
        all_findings = rslt["findings"]
        tlc = list(
            filter(
                lambda c: c != {},
                [f if f["scanSource"] == "twistlock_cve" else {} for f in all_findings],
            )
        )
        # tlc = rslt["twistlock_cve"]
        assert len(tlc) == 6, "finding count = 6"
        assert type(tlc[0]["score"]) is float, "score type"
        assert tlc[0]["finding"] == "CVE-2016-1000031", "finding = CVE-2016-1000031"
        assert tlc[0]["score"] == 9.8, "score = 9.8"
        assert (
            tlc[0]["description"]
            == "Apache Commons FileUpload before 1.3.3 DiskFileItem File Manipulation Remote Code Execution"
        ), "description"
        assert tlc[0]["severity"] == "critical", "severity = critical"
        assert (
            tlc[0]["link"]
            == "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-1000031"
        ), "link"
        assert (
            tlc[0]["package"] == "commons-fileupload_commons-fileupload-1.3.1-jenkins-2"
        ), "package"
        assert tlc[0]["packagePath"] is None, "packagePath = "

        asc = list(
            filter(
                lambda c: c != {},
                [f if f["scanSource"] == "anchore_cve" else {} for f in all_findings],
            )
        )
        assert asc[0]["finding"] == "CVE-2019-9948", "finding"
        assert (
            asc[0]["description"]
            == "Python-2.7.5\nhttps://nvd.nist.gov/vuln/detail/CVE-2019-9948"
        ), "description"
        assert asc[0]["link"] is None, "link"
        assert asc[0]["package"] == "Python-2.7.5", "package"
        assert (
            asc[0]["packagePath"] == "/opt/app-root/lib/python3.6/site-packages/pip"
        ), "package"

        assert asc[0]["severity"] == "critical", "severity"
        assert asc[1]["severity"] == "medium", "severity"
        assert asc[3]["severity"] == "high", "severity"

        acc = list(
            filter(
                lambda c: c != {},
                [f if f["scanSource"] == "anchore_comp" else {} for f in all_findings],
            )
        )
        assert acc[0]["severity"] == "ga_go", "severity: go"
        assert acc[1]["severity"] == "ga_go", "severity: go"
        assert acc[2]["severity"] == "ga_stop", "severity: stop"
        assert acc[3]["severity"] == "ga_go", "severity: go"
        assert acc[4]["severity"] == "ga_warn", "severity: warn"
        assert acc[5]["severity"] == "ga_stop", "severity: go"

        occ = list(
            filter(
                lambda c: c != {},
                [f if f["scanSource"] == "oscap_comp" else {} for f in all_findings],
            )
        )
        print(occ)
        assert occ[len(occ) - 1]["finding"] == "CCE-82168-6", "finding"
        assert (
            occ[len(occ) - 1]["description"]
            == "Log USBGuard daemon audit events using Linux Audit"
        ), "description"
        assert occ[len(occ) - 1]["severity"] == "medium", "severity(131)"
        assert occ[len(occ) - 3]["severity"] == "medium", "severity(155)"
        assert occ[len(occ) - 2]["severity"] == "medium", "severity(187)"
