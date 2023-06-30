import os

CI_PROJECT_DIR = os.getenv("CI_PROJECT_DIR")
if "pipeline-test-project" in CI_PROJECT_DIR:
    logging.info(
        "Skipping vat. Cannot push to VAT when working with pipeline test projects..."
    )
    sys.exit(0)
