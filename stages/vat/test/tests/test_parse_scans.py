import pytest
import argparse
import logging
import logging.handlers

import pipeline_job_gen
import unittest

pipeline_job_gen.logs = logging.getLogger("Tests")
formatter = logging.Formatter("%(levelname)-8s %(message)s")
console = logging.StreamHandler()
console.setFormatter(formatter)
LOG_FILE = "test_logging.out"
handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=(1048576 * 5), backupCount=3
)
handler.setFormatter(formatter)
pipeline_job_gen.logs.setLevel(logging.ERROR)
pipeline_job_gen.logs.addHandler(console)
pipeline_job_gen.logs.addHandler(handler)


class ParseJobsTestCase(unittest.TestCase):
    def test_parse_csvs_exception(self):

        parser = argparse.ArgumentParser(
            description="DCCSCR processing of CVE reports from various sources"
        )
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--api_url",
            nargs="?",
            const="http://localhost:4000/internal/import/scan",
            default="http://localhost:4000/internal/import/scan",
        )
        parser.add_argument("--job_id", nargs="?", const="0", default="0")
        parser.add_argument(
            "--commit_hash",
            nargs="?",
            const="f65d19452198ac1d55045756f2fce6c6b91b1d15",
            default="f65d19452198ac1d55045756f2fce6c6b91b1d15",
        )
        parser.add_argument(
            "--digest",
            nargs="?",
            const="abcdefghijklm1nopqstuvwxyz123456789123456789abcdefghijklmnopqrst",
            default="abcdefghijklm1nopqstuvwxyz123456789123456789abcdefghijklmnopqrst",
        )
        parser.add_argument(
            "--twistlock",
            nargs="?",
            const="./test/test_data",
            default="./test/test_data",
        )
        parser.add_argument(
            "--oscap", nargs="?", const="./test/test_data", default="./test/test_data"
        )
        parser.add_argument(
            "--anchore-sec",
            nargs="?",
            const="./test/test_data",
            default="./test/test_data",
        )
        parser.add_argument(
            "--anchore-gates",
            nargs="?",
            const="./test/test_data",
            default="./test/test_data",
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
        parser.add_argument("--dump_json", nargs="?", const="", default="")
        parser.add_argument("--use_json", nargs="?", const="", default="")
        parser.add_argument(
            "--out_file",
            nargs="?",
            const="",
            default="out.json",
        )

        test_args, notKnownArgs = parser.parse_known_args()
        if notKnownArgs:
            print(notKnownArgs)

        pipeline_job_gen.args = test_args
        with pytest.raises(Exception):
            assert pipeline_job_gen.create_api_call()

    def test_parse_csvs(self):
        parser = argparse.ArgumentParser(
            description="DCCSCR processing of CVE reports from various sources"
        )
        parser.add_argument(
            "--api_url",
            nargs="?",
            const="http://localhost:4000/internal/import/scan",
            default="http://localhost:4000/internal/import/scan",
        )
        parser.add_argument("--job_id", nargs="?", const="0", default="0")
        parser.add_argument(
            "--scan_date", nargs="?", const="2021-01-01", default="2021-01-01"
        )
        parser.add_argument(
            "--commit_hash",
            nargs="?",
            const="f65d19452198ac1d55045756f2fce6c6b91b1d15",
            default="f65d19452198ac1d55045756f2fce6c6b91b1d15",
        )
        parser.add_argument(
            "--container",
            nargs="?",
            const="VENDOR/PRODUCT/CONTAINER",
            default="VENDOR/PRODUCT/CONTAINER",
        )
        parser.add_argument("--version", nargs="?", const="0.0.2", default="0.0.2")
        parser.add_argument(
            "--digest",
            nargs="?",
            const="abcdefghijklm1nopqstuvwxyz123456789123456789abcdefghijklmnopqrst",
            default="abcdefghijklm1nopqstuvwxyz123456789123456789abcdefghijklmnopqrst",
        )
        parser.add_argument(
            "--twistlock",
            nargs="?",
            const="./test/test_data",
            default="./test/test_data",
        )
        parser.add_argument(
            "--oscap", nargs="?", const="./test/test_data", default="./test/test_data"
        )
        parser.add_argument(
            "--anchore-sec",
            nargs="?",
            const="./test/test_data",
            default="./test/test_data",
        )
        parser.add_argument(
            "--anchore-gates",
            nargs="?",
            const="./test/test_data",
            default="./test/test_data",
        )
        parser.add_argument(
            "--parent",
            nargs="?",
            const="VENDOR/PRODUCT/CONTAINER",
            default="VENDOR/PRODUCT/CONTAINER",
        )
        parser.add_argument(
            "--parent_version", nargs="?", const="0.0.1", default="0.0.1"
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
        parser.add_argument("--dump_json", nargs="?", const="", default="")
        parser.add_argument("--use_json", nargs="?", const="", default="")
        parser.add_argument(
            "--out_file",
            nargs="?",
            const="",
            default="out.json",
        )

        test_args, notKnownArgs = parser.parse_known_args()
        if notKnownArgs:
            print(notKnownArgs)

        pipeline_job_gen.args = test_args
        assert pipeline_job_gen.args == test_args
        rslt = pipeline_job_gen.create_api_call()
        assert type(rslt), dict

        # ------------------ twistlock ------------------
        all_findings = rslt["findings"]
        tlc = list(
            filter(
                lambda c: c != {},
                [f if f["scanSource"] == "twistlock_cve" else {} for f in all_findings],
            )
        )
        assert len(tlc) == 15, "finding count = 15"
        assert type(tlc[0]["score"]) is float, "score type"
        assert tlc[0]["finding"] == "CVE-2021-27218", "finding = CVE-2021-27218"
        assert tlc[0]["score"] == 7.5, "score = 7.5"
        assert (
            tlc[0]["description"]
            == "An issue was discovered in GNOME GLib before 2.66.7 and 2.67.x before 2.67.4. If g_byte_array_new_take() was called with a buffer of 4GB or more on a 64-bit platform, the length would be truncated modulo 2**32, causing unintended length truncation."
        ), "description"
        assert tlc[0]["severity"] == "moderate", "severity = moderate"
        assert (
            tlc[0]["link"] == "https://access.redhat.com/security/cve/CVE-2021-27218"
        ), "link"
        assert tlc[0]["package"] == "glib2-2.56.4-10.el8_4", "package"
        assert tlc[0]["packagePath"] is None, "packagePath = "

        # ------------------ anchore_cve ------------------
        asc = list(
            filter(
                lambda c: c != {},
                [f if f["scanSource"] == "anchore_cve" else {} for f in all_findings],
            )
        )
        assert asc[0]["finding"] == "CVE-2021-22876", "finding"
        assert (
            asc[0]["description"]
            == 'curl 7.1.1 to and including 7.75.0 is vulnerable to an "Exposure of Private Personal Information to an Unauthorized Actor" by leaking credentials in the HTTP Referer: header. libcurl does not strip off user credentials from the URL when automatically populating the Referer: HTTP request header field in outgoing HTTP requests, and therefore risks leaking sensitive data to the server that is the target of the second HTTP request.'
        ), "description"
        assert (
            asc[0]["link"] == "https://access.redhat.com/security/cve/CVE-2021-22876"
        ), "link"
        assert asc[0]["package"] == "curl-7.61.1-18.el8", "package"
        assert asc[0]["packagePath"] is None, "package"

        assert asc[0]["severity"] == "medium", "severity"
        assert asc[3]["severity"] == "low", "severity"

        # ------------------ anchore_comp ------------------
        acc = list(
            filter(
                lambda c: c != {},
                [f if f["scanSource"] == "anchore_comp" else {} for f in all_findings],
            )
        )
        assert acc[0]["severity"] == "ga_warn", "severity: warn"
        assert acc[1]["severity"] == "ga_stop", "severity: stop"

        # ------------------ oscap_comp ------------------
        occ = list(
            filter(
                lambda c: c != {},
                [f if f["scanSource"] == "oscap_comp" else {} for f in all_findings],
            )
        )
        assert occ[len(occ) - 1]["finding"] == "CCE-82168-6", "finding"
        assert (
            occ[len(occ) - 1]["description"]
            == "Log USBGuard daemon audit events using Linux Audit"
        ), "description"
        assert occ[len(occ) - 1]["severity"] == "medium", "severity(131)"
        assert occ[len(occ) - 3]["severity"] == "medium", "severity(155)"
        assert occ[len(occ) - 2]["severity"] == "medium", "severity(187)"
