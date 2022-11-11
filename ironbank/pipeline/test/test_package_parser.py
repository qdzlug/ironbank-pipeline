#!/usr/bin/env python3


import pytest
import inspect

from ironbank.pipeline.utils import package_parser
from ironbank.pipeline.utils import logger

log = logger.setup(name="test_package_parser")


@pytest.fixture
def package_classes():
    return {
        "YumPackage": {
            "name": "libpcap",
            "version": "1.9.1-5",
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
        "AptPackage": {
            "name": "openssl",
            "version": "1.1.1f-1ubuntu2.16",
            "good_url": "pool/main/o/openssl/openssl_1.1.1f-1ubuntu2.16_amd64.deb",
            "bad_urls": [
                "pool/main/o/openssl/openssl%$_.deb",
            ],
            "skip_url": "dists/pool/main/o/openssl/openssl_1.1.1f-1ubuntu2.16_amd64.deb",
        },
        "GoPackage": {
            "name": "goproxy/golang.org/x/tools",
            "version": "v0.0.0-20180917221912-90fa682c2a6e",
            "good_url": "goproxy/golang.org/x/tools/@v/v0.0.0-20180917221912-90fa682c2a6e.mod",
            "bad_urls": [
                "goproxy/golang.org/x/tools/%$.mod",
                "goproxy/golang.org/x/tools/@v/v0.0.0-20180917221912-90fa682c2a6e.example",
            ],
            "skip_url": "goproxy/golang.org/x/tools/@v/v0.0.0-20180917221912-90fa682c2a6e.zip",
        },
        "NullPackage": {
            "good_url": "gosum/lookup/go.uber.org/atomic@v1.5.0",
        },
    }


@pytest.mark.only
def test_init_all_package_types(package_classes):
    # get list of modules with name container "Package"
    for pkg_type in list(package_classes.keys()):
        # cast string to type
        PackageType = getattr(package_parser, pkg_type)
        if not inspect.isabstract(PackageType):
            log.info("Test successful init for %s package", pkg_type)
            pkg = PackageType(
                name="example", version="1.0", url="http://registry.com/example-1.0.rpm"
            )
            assert pkg.name == "example"
            assert pkg.version == "1.0"

            log.info("Test kind provided in init for %s package fails", pkg_type)
            with pytest.raises(TypeError) as te:
                PackageType(
                    kind="abc",
                    name="example",
                    version="1.0",
                    url="http://registry.com/example-1.0.abc",
                )
            assert "got an unexpected keyword argument 'kind'" in te.value.args[0]


@pytest.mark.only
def test_all_successful_parse_methods(package_classes):
    # log.info("Test all successful cases for parsing packages")
    for pkg_type, obj in package_classes.items():
        PackageType = getattr(package_parser, pkg_type)
        if not inspect.isabstract(PackageType):
            pkg = PackageType.parse(obj["good_url"])
            assert pkg is None or (pkg.name == obj.get("name"))
            assert pkg is None or (pkg.version == obj.get("version"))

            if obj.get("bad_urls"):
                log.info(pkg_type)
                with pytest.raises(ValueError):
                    for bad_url in obj["bad_urls"]:
                        pkg = PackageType.parse(bad_url)

            if obj.get("skip_url"):
                log.info(pkg_type)
                pkg = PackageType.parse(obj["skip_url"])
                assert pkg is None
