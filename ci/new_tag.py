import re
from pathlib import Path
from typing import Any

import semver
from git import Repo, TagReference
from pipeline.hardening_manifest import HardeningManifest
from pipeline.project import DsopProject


def extract_tag_details(
    tag: TagReference | str,
    format_regex: re.Pattern | str,
) -> dict[str, Any] | None:
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
    return tag_match.groupdict() if tag_match else None


def get_next_ib_tag(hardening_manifest: HardeningManifest, repo: Repo) -> str:
    """
    Get next tag value after parsing/sorting all exist tags.
    Use tag from hardening_manifest (hm) to determine which ib_tag semver part to bump.

    Tagging strategy:
    If first tag in repo: - tag: `1.0.0`

    HM tag stays same but gets updated: - tag: `1.0.1`

    HM tag is bumped: - tag: `1.1.0`
    """
    tags: list[dict[str, str | semver.Version]] = []
    ib_group, hm_group = ("ib_tag", "hm_tag")

    if not repo.tags:
        return "1.0.0"

    for tag in repo.tags:
        # for tag 8.8-ib-1.0.0, <hm_group>=8.8, <ib_group>=1.0.0
        tag_details = extract_tag_details(
            tag, rf"^(?P<{hm_group}>.*)-ib-(?P<{ib_group}>\d+\.\d+\.\d+)$"
        )
        # skip unmatched tags
        if tag_details:
            tag_details[ib_group] = semver.Version.parse(tag_details[ib_group])
            tags.append(tag_details)

    # repo.tags should be sorted, but re-sorting just in case
    latest_tag = sorted(tags, key=lambda tag: tag["ib_tag"])[-1]
    assert isinstance(latest_tag, semver.Version)
    next_tag = (
        latest_tag["ib_tag"].bump_minor()
        if hardening_manifest.image_tag != latest_tag["hm_tag"]
        else latest_tag["ib_tag"].bump_patch()
    )
    return f"{hardening_manifest.image_tag}-ib-{next_tag}"


def main() -> None:
    """Provide next tag for cht project"""
    repo = Repo()
    repo.remote().fetch(tags=True)
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    next_tag = get_next_ib_tag(hardening_manifest, repo)
    print(next_tag)


if __name__ == "__main__":
    main()
