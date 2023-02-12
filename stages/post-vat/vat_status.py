#!/usr/bin/env python3

import os
import json
from pathlib import Path
from typing import Any
import anybadge

from ironbank.pipeline.utils import logger

log = logger.setup("VAT Status Badges")


def get_vat_data() -> tuple[str, float, str]:
    """Retrieve image status data from VAT response file"""
    with Path(f"{os.environ['ARTIFACT_STORAGE']}/vat/vat_response.json").open(
        mode="r",
        encoding="utf-8",
    ) as f:
        vat_response = json.load(f)
    log.info("Get VAT status for project")
    image_state_data: dict = vat_response["image"]["state"]
    abc_status: str = image_state_data["abc"]
    ora_score: float = image_state_data["ora"]
    image_status: str = image_state_data["imageStatus"]
    return (abc_status, ora_score, image_status)


def create_svg(badge_name: str, value: Any, thresholds: dict, svg_name: str) -> None:
    """Create svg for project badge"""
    badge_color = thresholds.get(value, "light_grey")
    badge = anybadge.Badge(
        label=badge_name,
        value=value,
        default_color=badge_color,
    )
    svg_file = Path(f"{os.environ['BADGE_DIRECTORY']}{svg_name}")
    badge.write_badge(svg_file)


def main() -> None:
    """Main method"""
    # TODO: Ensure threshold colors match the VAT's colorways
    abc_thresholds = {
        "Compliant": "green",
        "Non-compliant": "red",
    }
    ora_thresholds = {
        100: "green",
        70: "yellow",
        50: "orange",
        30: "red",
    }
    image_status_thresholds = {
        "Approved": "green",
        "Conditionally Approved": "orange",
        "Verified": "steelblue",
        "Unverified": "light_grey",
    }
    abc_status, ora_score, image_status = get_vat_data()
    create_svg(
        "ABC Status",
        abc_status,
        abc_thresholds,
        "abc_status.svg",
    )
    create_svg(
        "ORA Score",
        ora_score,
        ora_thresholds,
        "ora_score.svg",
    )
    create_svg(
        "Image Status",
        image_status,
        image_status_thresholds,
        "image_status.svg",
    )


if __name__ == "__main__":
    main()
