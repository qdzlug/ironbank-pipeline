#!/usr/bin/env python3

import inspect

import pytest

from ironbank.pipeline.utils import logger, package_parser

log = logger.setup(name="test_package_parser")


@pytest.fixture
def package_classes():
    # Provides test URLs and verification data to hit unique cases for each package parser
    #   good_url - URL that will be parsed successfully
    #   bad_urls - List of URLs that cannot be parsed and will throw exceptions
    #   skip_url - URL that will be skipped (return None)
    return {
        "RpmPackage": {
            "name": "libpcap",
            "version": "1.9.1-5.el8.x86_64",
            "good_url": "ubigroup-8/Packages/l/libpcap-1.9.1-5.el8.x86_64.rpm",
            "bad_urls": [
                "ubigroup-8/Packages/l/libpcap-%$.rpm",
            ],
            "skip_url": "repodata/ubigroup-8/Packages/l/libpcap-1.9.1-5.el8.x86_64.rpm",
        },
        "PypiPackage": {
            "name": "pip",
            "version": "22.3.1",
            "good_url": "packages/pip/22.3.1/pip-22.3.1-py3-none-any.whl",
            "bad_urls": [
                "packages/pip/pip%$-.whl",
            ],
            "skip_url": "simple/packages/pip/22.3.1/pip-.whl",
        },
        "DebianPackage": {
            "name": "openssl",
            "version": "1.1.1f-1ubuntu2.16_amd64",
            "good_url": "pool/main/o/openssl/openssl_1.1.1f-1ubuntu2.16_amd64.deb",
            "bad_urls": [
                "pool/main/o/openssl/openssl%$_.deb",
            ],
            "skip_url": "dists/pool/main/o/openssl/openssl_1.1.1f-1ubuntu2.16_amd64.deb",
        },
        "ApkPackage": {
            "name": "libgcc",
            "version": "12.2.1_git20220924-r4",
            "good_url": "apk-main/x86_64/libgcc-12.2.1_git20220924-r4.apk",
            "skip_url": "APKINDEX/x86_64/libgcc-12.2.1_git20220924-r4.apk",
            "bad_urls": ["x86_64/libgcc-12.2.1_git20220924-r4"],
        },
        "GoPackage": {
            "name": "goproxy/golang.org/x/tools",
            "version": "v0.0.0-20180917221912-90fa682c2a6e",
            "good_url": "goproxy/golang.org/x/tools/@v/v0.0.0-20180917221912-90fa682c2a6e.mod",
            "bad_urls": [
                "goproxy/golang.org/x/tools/%$.mod",
                "goproxy/golang.org/x/tools/@v/v0.0.0-20180917221912-90fa682c2a6e.md",
            ],
            "skip_url": "goproxy/golang.org/x/tools/@v/v0.0.0-20180917221912-90fa682c2a6e.zip",
        },
        "NpmPackage": {
            "name": "callsite",
            "version": "1.0.0",
            "good_url": "callsite/-/callsite-1.0.0.tgz",
            "bad_urls": [
                "callsite/-/callsite.tgg",
            ],
            "skip_url": "callsite/callsite-1.0.0.tgz",
        },
        "RubyGemPackage": {
            "name": "getoptlong",
            "version": "0.1.1",
            "good_url": "gems/getoptlong-0.1.1.gem",
            "bad_urls": [
                "gems/getoptlong.geeem",
            ],
            "skip_url": "gemsies/getoptlong-0.1.1.gem",
        },
        "NullPackage": {
            "good_url": "gosum/lookup/go.uber.org/atomic@v1.5.0",
        },
    }


def test_init_all_package_types(package_classes):
    # get list of modules with name container "Package"
    for pkg_type in list(package_classes.keys()):
        # cast string to type
        PackageType = getattr(package_parser, pkg_type) # pylint: disable=C0103
        if not inspect.isabstract(PackageType):
            log.info("Test successful init for %s package", pkg_type)
            pkg = PackageType(
                name="example", version="1.0", url="http://registry.com/example-1.0.rpm"
            )
            assert pkg.name == "example"
            assert pkg.version == "1.0"

            log.info("Test kind provided in init for %s package fails", pkg_type)
            with pytest.raises(TypeError) as e:
                PackageType(
                    kind="abc",
                    name="example",
                    version="1.0",
                    url="http://registry.com/example-1.0.abc",
                )
            assert "got an unexpected keyword argument 'kind'" in e.value.args[0]


def test_all_successful_parse_methods(package_classes):
    for pkg_type, obj in package_classes.items():
        PackageType = getattr(package_parser, pkg_type) # pylint: disable=C0103
        if not inspect.isabstract(PackageType):
            log.info("Test %s successfully parses %s", pkg_type, obj["good_url"])
            pkg = PackageType.parse(obj["good_url"])
            assert pkg is None or (pkg.name == obj.get("name"))
            assert pkg is None or (pkg.version == obj.get("version"))

            if obj.get("bad_urls"):
                for bad_url in obj["bad_urls"]:
                    with pytest.raises(ValueError):
                        log.info("Test %s throws ValueError on %s", pkg_type, bad_url)
                        pkg = PackageType.parse(bad_url)

            if obj.get("skip_url"):
                log.info("Test %s skips %s", pkg_type, obj["skip_url"])
                pkg = PackageType.parse(obj["skip_url"])
                assert pkg is None
