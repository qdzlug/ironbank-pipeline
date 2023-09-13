from git import Repo
from pipeline.hardening_manifest import HardeningManifest
from pipeline.project import DsopProject
from common.utils.ibtag import IBTagHelper


def main() -> None:
    """Provide next tag for cht project"""
    repo = Repo()
    repo.remote().fetch(tags=True)
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    next_tag = IBTagHelper.get_next_tag(hardening_manifest, repo)
    print(next_tag)


if __name__ == "__main__":
    main()
