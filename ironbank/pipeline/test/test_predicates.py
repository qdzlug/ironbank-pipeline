from ironbank.pipeline.utils import predicates
from ironbank.pipeline.utils import logger

log = logger.setup("test_predicates")


def test_get_predicates():
    log.info("Test successful returns")
    assert predicates.get_predicate_files()
    assert predicates.get_unattached_predicates()
