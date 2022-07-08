import os
import sys

import pytest

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

import utils.package_parser as pp  # noqa E402


@pytest.fixture
def mock_urls():
    return {
        "yum_repodata": "repodata/repomd.xml",
        "yum": "Packages/p/testName-0.0.0-0.el8.x86_64.rpm",
        "go": "testName/@v/v0.0.0.mod",
        "go_nomatch": "testName/@bad/v0.0.0.mod",
        "go_zip": "testName/@v/v0.0.0.zip",
        "go_badext": "testName/@v/v0.0.0.bad",
        "pypi": "packages/testName/0.0.0/testFileName.whl",
        "pypi_nomatch": "packages/testName/testFileName-0.0.0.whl",
        "pypi_simple": "simple/markupsafe/",
        "npm": "testName/-/testName-0.0.0.tgz",
        "npm_nomatch": "testName/-/badName-0.0.0.tgz",
        "ruby": "gems/testName-0.0.0.gem",
        "ruby_nomatch": "gems/testNoMatch",
        "null": "nullURL",
    }


def test_yum_parse(mock_urls):
    with pytest.raises(ValueError):
        pp.YumPackage.parse(mock_urls["null"])

    assert pp.YumPackage.parse(mock_urls["yum_repodata"]) is None

    yumPkg = pp.YumPackage.parse(mock_urls["yum"])
    assert yumPkg.kind == "rpm"
    assert yumPkg.name == "testName"
    assert yumPkg.version == "0.0.0-0"
    assert yumPkg.url == "Packages/p/testName-0.0.0-0.el8.x86_64.rpm"


def test_go_parse(mock_urls):
    with pytest.raises(ValueError):
        pp.GoPackage.parse(mock_urls["go_nomatch"])
    with pytest.raises(ValueError):
        pp.GoPackage.parse(mock_urls["go_badext"])

    assert pp.GoPackage.parse(mock_urls["go_zip"]) is None

    goPkg = pp.GoPackage.parse(mock_urls["go"])
    assert goPkg.kind == "go"
    assert goPkg.name == "testName"
    assert goPkg.version == "v0.0.0"
    assert goPkg.url == "testName/@v/v0.0.0.mod"


def test_pypi_parse(mock_urls):
    with pytest.raises(ValueError):
        pp.PypiPackage.parse(mock_urls["pypi_nomatch"])

    assert pp.PypiPackage.parse(mock_urls["pypi_simple"]) is None

    pypiPkg = pp.PypiPackage.parse(mock_urls["pypi"])
    assert pypiPkg.kind == "python"
    assert pypiPkg.name == "testName"
    assert pypiPkg.version == "0.0.0"
    assert pypiPkg.url == "packages/testName/0.0.0/testFileName.whl"


def test_npm_parse(mock_urls):
    with pytest.raises(ValueError):
        pp.NpmPackage.parse(mock_urls["npm_nomatch"])

    assert pp.NpmPackage.parse(mock_urls["null"]) is None

    npmPkg = pp.NpmPackage.parse(mock_urls["npm"])
    assert npmPkg.kind == "npm"
    assert npmPkg.name == "testName"
    assert npmPkg.version == "0.0.0"
    assert npmPkg.url == "testName/-/testName-0.0.0.tgz"


def test_ruby_parse(mock_urls):
    with pytest.raises(ValueError):
        pp.RubyGemPackage.parse(mock_urls["ruby_nomatch"])

    assert pp.RubyGemPackage.parse(mock_urls["null"]) is None

    rubyPkg = pp.RubyGemPackage.parse(mock_urls["ruby"])
    assert rubyPkg.kind == "rubygem"
    assert rubyPkg.name == "testName"
    assert rubyPkg.version == "0.0.0"
    assert rubyPkg.url == "gems/testName-0.0.0.gem"


def test_null_parse(mock_urls):
    assert pp.NullPackage.parse(mock_urls["null"]) is None
