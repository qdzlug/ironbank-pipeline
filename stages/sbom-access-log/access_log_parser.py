import os
import sys
import argparse

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from utils import logger  # noqa: E402
from utils.package_parser import AccessLogFileParser  # noqa: E402

log = logger.setup(name="access_log_parser", format="| %(levelname)-5s | %(message)s")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script used to parse access_log files"
    )
    parser.add_argument(
        "--allow-errors",
        action="store_true",
        help="allow parsing to continue upon encountering an error",
    )
    parser.add_argument(
        "file",
        type=str,
        help="path to access_log file",
    )
    args = parser.parse_args()

    try:
        AccessLogFileParser.parse(file=args.file)
    except OSError:
        log.error(f"Unable to open file: {args.file}")
        sys.exit(1)
    except ValueError as e:
        log.error(f"Unable to parse access_log: {args.file}")
        log.error(e)
        if not args.allow_errors:
            sys.exit(1)
    except Exception:
        log.exception("Exception: Unknown exception")
        # TODO: Consider adding custom exception handler to reduce repetition
        if not args.allow_errors:
            sys.exit(1)
