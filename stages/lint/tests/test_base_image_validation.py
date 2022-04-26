#!/usr/bin/env python3
from operator import contains
import sys
import os
import logging
import pytest
import subprocess


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_image_validation import skopeo_inspect_base_image # noqa E402

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")

@pytest.fixture
def good_base_image():
    return ["redhat/ubi/ubi8", "8.5"]

@pytest.fixture
def bad_base_image():
    return ["redhat/ubi/ubi8", "8.100"]



def test_skopeo_inspect_good_base_image(good_base_image):
    assert skopeo_inspect_base_image(good_base_image[0], good_base_image[1]) == None

def test_skopeo_inspect_bad_base_image(bad_base_image):
    with pytest.raises(SystemExit) as exc_info:
        skopeo_inspect_base_image(bad_base_image[0], bad_base_image[1])

    assert exc_info.type == SystemExit

