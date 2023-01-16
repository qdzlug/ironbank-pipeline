from ironbank.pipeline.utils.predicates import Predicates
from ironbank.pipeline.utils import logger

log = logger.setup("test_predicates")


def test_get_predicates():
    log.info("Test successful returns")
    assert Predicates.get_predicate_files()
    assert Predicates.unattached_predicates
