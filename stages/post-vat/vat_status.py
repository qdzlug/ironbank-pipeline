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
    abc_status: str = (
        "Compliant With Warnings"
        if (
            image_state_data["factors"]["abc"]["hasAbcWarnings"]
            and image_state_data["abc"] == "Compliant"
        )
        else image_state_data["abc"]
    )
    ora_score: float = image_state_data["ora"]
    percent_verified: str = image_state_data["percentVerified"]
    return (abc_status, ora_score, percent_verified)


def create_svg(badge_name: str, value: Any, thresholds: dict, svg_name: str) -> None:
    """Create svg for project badge"""
    badge = anybadge.Badge(
        label=badge_name,
        value=value,
        thresholds=thresholds,
        default_color="light_grey",
    )
    svg_file = Path(f"{os.environ['BADGE_DIRECTORY']}/{svg_name}")
    badge.write_badge(svg_file)


def main() -> None:
    """Main method"""
    abc_thresholds = {
        "Compliant": "#217645",
        "Compliant With Warnings": "#A85D00",
        "Non-compliant": "#C91C00",
    }
    percent_thresholds = {
        100: "#217645",
        70: "#A85D00",
        40: "#C91C00",
    }
    abc_status, ora_score, percent_verified = get_vat_data()
    create_svg(
        "ABC Status",
        abc_status,
        abc_thresholds,
        "abc_status.svg",
    )
    create_svg(
        "ORA Score",
        ora_score,
        percent_thresholds,
        "ora_score.svg",
    )
    create_svg(
        "Findings Verified",
        percent_verified,
        percent_thresholds,
        "percent_verified.svg",
    )


if __name__ == "__main__":
    main()
