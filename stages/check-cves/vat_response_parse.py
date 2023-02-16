#!/usr/bin/env python3

import json
import sys
import os
from pathlib import Path

from ironbank.pipeline.vat_container_status import is_approved


def main():
    """
    Calls is_approved method in ironbank.pipeline.vat_container_status
    """

    vat_response = {}
    with Path(f"{os.environ['ARTIFACT_STORAGE']}/vat/vat_response.json").open(
        mode="r", encoding="utf-8"
    ) as f:
        vat_response = json.load(f)

    exit_code = is_approved(vat_response, True)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
