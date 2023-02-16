#!/usr/bin/env python3

import pytest
from ironbank.pipeline.utils import logger
from ironbank.pipeline import vat_container_status
import random
import string


log = logger.setup("test_finding_status")


def mock_vat_finding(
    identifier: str = None,
    scanner_name: str = None,
    severity: str = None,
    package: str = None,
    package_path: str = None,
    inherits_from: str = None,
    state: dict[str, str] = None,
):
    finding = {
        "identifier": identifier or f"CVE-{random.randint(10000, 20000)}",
        "scannerName": scanner_name
        or random.choice(["Twistlock CVE", "OSCAP Compliance", "Anchore CVE"]),
        "severity": severity or random.choice(["Low", "Medium", "High", "Critical"]),
        "inheritsFrom": inherits_from or random.choice(["", "redhat/ubi/ubi8"]),
        "state": state
        or {
            "findingStatus": random.choice(
                [
                    "Needs Justification",
                    "Needs Rework",
                    "Need Reverified",
                    "Justified",
                    "Verified",
                ]
            )
        },
    }
    # package must be defined for package path to be defined
    assert not (package_path and not package)

    generate_random_string = lambda num_chars, extra_chars: ''.join([random.choice(string.ascii_letters+extra_chars) for _ in range(num_chars)]) # noqa E731

    finding = (
        finding
        if package is None
        else {**finding, "package": package}
        if package
        else {
            **finding,
            "package": f"{generate_random_string(10, '-_+0123')}.{random.choice(['.whl', 'rpm', '.tar'])}",
        }
    )
    package = finding.get("package", "")
    finding = (
        finding
        if package_path is None
        else {**finding, "package_path": package_path}
        if package_path
        else {
            **finding,
            "package_path": f"{generate_random_string(10, '-_+0123/')}/{package}",
        }
    )

    return finding


@pytest.fixture
def mock_vat_response():
    return {
        "image": {
            "imageName": "",
            "tag": "",
            "vatUrl": "https://vat-is-cool.org",
            "state": {
                "imageStatus": "Approved",
                "reason": "Auto Approval example",
                "factors": {"caReview": {"value": "Approved"}},
            },
            "findings": [mock_vat_finding(**random.choice([{}, {'package': ''}, {'package': '', 'package_path': ''}])) for _ in range(50)],
        }
    }


def test_log_unverified_findings(monkeypatch, mock_vat_response):
    log.info("Test unverified findings found returns 100")
    mock_vat_response['image']['findings'] += [mock_vat_finding(state={"findingStatus": "Needs Rework"})]
    monkeypatch.setattr(vat_container_status, "log_findings", lambda findings, level: None)
    assert vat_container_status.log_unverified_findings(mock_vat_response) == 100

    log.info("Test no unverified findings found returns 0")
    mock_vat_response['image']['findings'] = [mock_vat_finding(state={"findingStatus": "Verified"})]
    assert vat_container_status.log_unverified_findings(mock_vat_response) == 0
