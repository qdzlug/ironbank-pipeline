import pytest
import argparse
import logging
import logging.handlers

import vat_import
import unittest

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
        test_args, notKnownArgs = parser.parse_known_args()
        if notKnownArgs:
            print(notKnownArgs)

        vat_import.args = test_args
        with pytest.raises(Exception):
            assert vat_import.parse_csvs()

    def test_parse_csvs(self):

        parser = argparse.ArgumentParser(description="SQL Agent")
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--csv_dir",
            nargs="?",
            const="./stages/vat/test/test_data",
            default="./stages/vat/test/test_data",
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
        test_args, notKnownArgs = parser.parse_known_args()
        if notKnownArgs:
            print(notKnownArgs)

        vat_import.args = test_args
        rslt = vat_import.parse_csvs()
        assert type(rslt), dict

        # twistlock
        tlc = rslt["twistlock_cve"]
        assert tlc["finding"].count() == 6, "finding count = 6"
        assert tlc["score"].dtype == "float64", "score type"
        assert tlc["finding"][0] == "CVE-2016-1000031", "finding = CVE-2016-1000031"
        assert tlc["score"][0] == 9.8, "score = 9.8"
        assert (
            tlc["description"][0]
            == "Apache Commons FileUpload before 1.3.3 DiskFileItem File Manipulation Remote Code Execution"
        ), "description"
        assert tlc["severity"][0] == "critical", "severity = critical"
        assert (
            tlc["link"][0]
            == "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-1000031"
        ), "link"
        assert (
            tlc["package"][0] == "commons-fileupload_commons-fileupload-1.3.1-jenkins-2"
        ), "package"
        assert tlc["package_path"][0] is None, "package_path = "

        asc = rslt["anchore_cve"]
        assert asc.at[0, "finding"] == "CVE-2019-9948", "finding"
        assert (
            asc.at[0, "description"]
            == "Python-2.7.5\nhttps://nvd.nist.gov/vuln/detail/CVE-2019-9948"
        ), "description"
        assert asc.at[0, "link"] is None, "link"
        assert asc.at[0, "package"] == "Python-2.7.5", "package"
        assert (
            asc.at[0, "package_path"] == "/opt/app-root/lib/python3.6/site-packages/pip"
        ), "package"

        assert asc.at[0, "severity"] == "Critical", "severity"
        assert asc.at[1, "severity"] == "Medium", "severity"
        assert asc.at[3, "severity"] == "High", "severity"

        acc = rslt["anchore_comp"]
        assert acc.at[0, "severity"] == "ga_go", "severity: go"
        assert acc.at[1, "severity"] == "ga_go", "severity: go"
        assert acc.at[2, "severity"] == "ga_stop", "severity: stop"
        assert acc.at[3, "severity"] == "ga_go", "severity: go"
        assert acc.at[4, "severity"] == "ga_warn", "severity: warn"
        assert acc.at[5, "severity"] == "ga_stop", "severity: go"

        osc = rslt["oscap_cve"]
        assert osc.at[0, "finding"] == "CVE-2019-15688", "finding"
        assert osc.at[0, "description"] == "", "description"
        assert osc.at[0, "package"] == "libvncserver", "package"
        assert osc.at[0, "severity"] == "important", "severity(1)"
        assert osc.at[1, "severity"] == "low", "severity(3)"
        assert osc.at[2, "severity"] == "critical", "severity(6)"
        assert osc.at[3, "severity"] == "moderate", "severity(7)"

        occ = rslt["oscap_comp"]
        assert occ.at[137, "finding"] == "OL07-00-040820", "finding"
        assert (
            occ.at[137, "description"]
            == "Verify Any Configured IPSec Tunnel Connections"
        ), "description"
        assert occ.at[137, "severity"] == "medium", "severity(131)"
        assert occ.at[155, "severity"] == "low", "severity(155)"
        assert occ.at[187, "severity"] == "high", "severity(187)"
