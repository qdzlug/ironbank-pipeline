#!/usr/bin/env python3
import sys
import os
import logging
import pytest
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hardening_manifest import HardeningManifest  # noqa E402

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")


@pytest.fixture
def load_good_labels():
    return {
        "org.opencontainers.image.title": "ubi8-minimal",
        "org.opencontainers.image.description": "Red Hat Universal Base Images (UBI) \
            are OCI-compliant container base operating system images with complementary \
            runtime languages and packages that are freely redistributable.",
        "org.opencontainers.image.licenses": "Apache v2",
        "org.opencontainers.image.url": "https://catalog.redhat.com/software/container-stacks/detail/5ec53f50ef29fd35586d9a56",  # noqa: E501
        "org.opencontainers.image.vendor": "Red Hat",
        "org.opencontainers.image.version": "8.3",
        "mil.dso.ironbank.image.keywords": "ubi, minimal, base, test",
        "mil.dso.ironbank.image.type": "commercial",
        "mil.dso.ironbank.product.name": "UBI8-minimal",
    }


@pytest.fixture
def load_bad_labels():
    return {
        "org.opencontainers.image.title": "ubi8-minimal",
        "org.opencontainers.image.description": "Red Hat Universal Base Images (UBI) \
            are OCI-compliant container base operating system images with complementary \
            runtime languages and packages that are freely redistributable.",
        "org.opencontainers.image.licenses": "FIXME",
        "org.opencontainers.image.url": "https://catalog.redhat.com/software/container-stacks/detail/5ec53f50ef29fd35586d9a56",  # noqa: E501
        "org.opencontainers.image.vendor": "Red Hat",
        "org.opencontainers.image.version": "8.3",
        "mil.dso.ironbank.image.keywords": "ubi, minimal, base, test",
        "mil.dso.ironbank.image.type": "commercial",
        "mil.dso.ironbank.product.name": "UBI8-minimal",
    }


@pytest.fixture
def load_good_maintainers():
    return {
        "name": "Josh Eason",
        "username": "jeason",
        "email": "josheason@seed-innovations.com",
    }


@pytest.fixture
def load_bad_maintainers():
    return {
        "name": "FIXME",
        "username": "jeason",
        "email": "josheason@seed-innovations.com",
    }


@pytest.fixture
def hm():
    return HardeningManifest(
        Path(Path(__file__).absolute().parent, "mocks/mock_hardening_manifest.yaml")
    )


def test_find_fixme(
    hm, load_good_labels, load_good_maintainers, load_bad_labels, load_bad_maintainers
):

    assert hm.check_for_fixme(load_good_labels) == []
    assert hm.check_for_fixme(load_good_maintainers) == []
    assert hm.check_for_fixme(load_bad_labels) == ["org.opencontainers.image.licenses"]
    assert hm.check_for_fixme(load_bad_maintainers) == ["name"]