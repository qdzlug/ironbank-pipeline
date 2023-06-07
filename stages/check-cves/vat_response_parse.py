#!/usr/bin/env python3

import json
import os
import sys
from pathlib import Path

from ironbank.pipeline.vat_container_status import log_unverified_findings


def main() -> None:
    """Calls log_findings_by_status method in
    ironbank.pipeline.vat_container_status."""
    vat_response: dict = json.loads(
        Path(f"{os.environ['ARTIFACT_STORAGE']}/vat/vat_response.json").read_text(
            encoding="utf-8"
        )
    )
    exit_code = log_unverified_findings(vat_response)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
