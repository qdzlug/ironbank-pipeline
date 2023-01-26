from ironbank.pipeline.utils.predicates import Predicates
from ironbank.pipeline.utils import logger

log = logger.setup("test_predicates")


def test_get_predicates():
    log.info("Test successful returns")
    predicates = Predicates()
    assert predicates.get_predicate_files()
    assert predicates.unattached_predicates
