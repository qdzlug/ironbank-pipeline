#!/usr/bin/env python3
from pathlib import Path
import sys
import os
import json

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)


from classes.project import DsopProject  # noqa: E402
from classes.apis import VatAPI  # noqa: E402
from classes.utils import logger  # noqa: E402
from hardening_manifest import Hardening_Manifest  # noqa: E402
from vat_container_status import is_approved  # noqa: E402


def create_api_findings_artifact(vat_response: dict) -> None:
    filename = Path(os.environ["ARTIFACT_DIR"], "vat_api_findings.json")
    with filename.open(mode="w") as f:
        json.dump(vat_response, f)


def create_approval_artifact(approval_status: str, approval_comment: str) -> None:
    filename = Path(os.environ["ARTIFACT_DIR"], "image_approval.json")
    image_approval = {
        "IMAGE_APPROVAL_STATUS": approval_status,
        "IMAGE_APPROVAL_TEXT": approval_comment,
    }
    with filename.open(mode="w") as f:
        json.dump(image_approval, f)


def main():
    # approval_status, approval_text = _get_vat_findings_api(
    #     os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"]
    # )

    # Get logging level, set manually when running pipeline
    logLevel = os.environ.get("LOGLEVEL", "INFO").upper()
    logFormat = (
        "%(levelname)s [%(filename)s:%(lineno)d]: %(message)s"
        if logLevel == "DEBUG"
        else "%(levelname)s: %(message)s"
    )
    log = logger.setup(
        name="lint.container_status_check", level=logLevel, format=logFormat
    )

    dsop_project = DsopProject()
    hardening_manifest = Hardening_Manifest(dsop_project.hardening_manifest_path)
    vat_api = VatAPI(url=os.environ["VAT_BACKEND_SERVER_ADDRESS"])
    vat_response = vat_api.get_image(
        image_name=hardening_manifest.image_name, image_tag=hardening_manifest.image_tag
    )

    log.debug(f"VAT response\n{vat_response}")
    create_api_findings_artifact(vat_response)

    approved, _, approval_status, approval_comment = is_approved(vat_response, False)
    approval_status = approval_status.lower().replace(" ", "_")

    log.debug("updated Approval Status: {approval_status}")
    create_approval_artifact(approval_status, approval_comment)

    if approved:
        log.info("This container is noted as an approved image in VAT")
    elif os.environ["CI_COMMIT_BRANCH"] != "master":
        log.warning("This container is not noted as an approved image in VAT")
    else:
        log.error("This container is not noted as an approved image in VAT")
        log.error("Failing pipeline")
        sys.exit(1)


if __name__ == "__main__":
    main()
