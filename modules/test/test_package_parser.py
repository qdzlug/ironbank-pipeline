import os
import sys
import pathlib

import pytest

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

import utils.package_parser as pp

@pytest.fixture
def mock_urls():
    return {
            'yum_repodata' : 'repodata/repomd.xml',
            'yum': 'Packages/p/testName-0.0.0-0.el8.x86_64.rpm',
            'go': '',
            'pypi': '',
            'npm': '',
            'ruby': 'gems/testName-0.0.0.gem',
            'ruby_nomatch': 'gems/testNoMatch',
            'null': 'nullURL'
        }
    

def test_yum_parse(mock_urls):
    with pytest.raises(ValueError):
        pp.YumPackage.parse(mock_urls['null'])
    
    assert pp.YumPackage.parse(mock_urls['yum_repodata']) == None

    yumPkg = pp.YumPackage.parse(mock_urls['yum'])
    assert yumPkg.kind == 'rpm'
    assert yumPkg.name == 'testName'
    assert yumPkg.version == '0.0.0-0'
    assert yumPkg.url == 'Packages/p/testName-0.0.0-0.el8.x86_64.rpm'


def test_go_parse(mock_urls):
    with pytest.raises(ValueError):
        pp.GoPackage.parse(mock_urls['null'])
    
    goPkg = pp.GoPackage.parse(mock_urls['yum'])
    assert goPkg.kind == 'rpm'
    assert goPkg.name == 'testName'
    assert goPkg.version == '0.0.0-0'
    assert goPkg.url == ''

def test_pypi_parse():
    pass

def test_npm_parse():
    pass



def test_ruby_parse(mock_urls):
    with pytest.raises(ValueError):
        pp.RubyGemPackage.parse(mock_urls['ruby_nomatch'])
    
    assert pp.YumPackage.parse(mock_urls['null']) == None

    rubyPkg = pp.RubyGemPackage.parse(mock_urls['ruby'])
    assert rubyPkg.kind == 'rubygem'
    assert rubyPkg.name == 'testName'
    assert rubyPkg.version == '0.0.0'
    assert rubyPkg.url == 'gems/testName-0.0.0.gem'

def test_null_parse(mock_urls):
    assert pp.NullPackage.parse(mock_urls['null']) == None
