import sys
import os

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from classes.project import DsopProject  # noqa E402


def main():
    dsop_project = DsopProject()
    dsop_project.validate_files_exist()
    dsop_project.validate_clamav_whitelist_config()
    dsop_project.validate_trufflehog_config()
    dsop_project.validate_dockerfile()


if __name__ == "__main__":
    main()
