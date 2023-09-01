from pathlib import Path
from typing import Any
import re

import semver
from git import Repo, TagReference

from pipeline.hardening_manifest import HardeningManifest
from pipeline.project import DsopProject


def extract_tag_details(
    tag: TagReference | str,
    format_regex: re.Pattern | str,
) -> dict[str, Any]:
    """
    Extracts partial tag from a Git tag using a regular expression.

    This function takes a Git tag (represented as a git.TagReference object or string)
    and extracts a substring based on the provided regular expression pattern and tag group.

    The tag_group can be an index value (int) or named group value (str)
    """
    # convert to re.Pattern if passed as str
    if not isinstance(format_regex, re.Pattern):
        format_regex = re.compile(format_regex)
    # remove ref path from tag if TagReference
    if isinstance(tag, TagReference):
        tag = Path(tag.path).name
    tag_match = format_regex.match(tag)
    assert tag_match, f"No match found for {tag} with regex {format_regex}"
    return tag_match.groupdict()


def main() -> None:
    """Provide next tag for cht project"""
    repo = Repo()
    repo.remote().fetch(tags=True)
    tags = []
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    ib_tag, hm_tag = ("ib_tag", "hm_tag")
    for tag in repo.tags:
        tag_details: dict[str, Any] = extract_tag_details(
            tag, rf"^(?P<{ib_tag}>\d+\.\d+\.\d+)-ib-(?P<{hm_tag}>.*)$"
        )
        tag_details[ib_tag] = semver.Version.parse(tag_details[ib_tag])
        tags.append(tag_details)

    # repo.tags should be sorted, but re-sorting just in case
    latest_tag = sorted(tags, key=lambda tag: tag["ib_tag"])[-1]
    next_tag = (
        latest_tag["ib_tag"].bump_minor()
        if hardening_manifest.image_tag != latest_tag["hm_tag"]
        else latest_tag["ib_tag"].bump_patch()
    )

    print(f"{next_tag}-ib-{hardening_manifest.image_tag}")


if __name__ == "__main__":
    main()
