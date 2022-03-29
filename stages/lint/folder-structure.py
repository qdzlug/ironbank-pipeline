import sys
import os

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from project import CHT_Project  # noqa E402


def main():
    cht_project = CHT_Project()
    cht_project.validate_files_exist()
    cht_project.validate_clamav_whitelist_config()
    cht_project.validate_trufflehog_config()


if __name__ == "__main__":
    main()
