import sys
import os
import argparse
import json
from utils.package_parser import AccessLogParser
from utils import logger

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

    access_log_parser = AccessLogParser(
        file=args.file, repos=json.load(open(os.environ.get("ACCESS_LOG_REPOS"), "r"))
    )
    try:
        access_log_parser.parse_access_log()
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
