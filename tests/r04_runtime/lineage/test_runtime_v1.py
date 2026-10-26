"""Thin pytest wrapper; future exact approved plugin supplies runtime_v1_api.

No automatic candidate loader. Without the separately approved fixture this
module cannot pass tests and must be reported as unavailable/not_run.
"""
import pytest
from protocol_suite import CASES as PROTOCOL_CASES
from parser_suite import CASES as PARSER_CASES
from authority_metadata_suite import CASES as METADATA_CASES


CASES = ([('protocol', check) for check in PROTOCOL_CASES]
         + [('parser', check) for check in PARSER_CASES]
         + [('metadata-provisional', check) for check in METADATA_CASES])


@pytest.mark.parametrize('family,check', CASES,
                         ids=[family + '-' + check.__name__ for family, check in CASES])
def test_runtime_v1(family, check, runtime_v1_api):
    check(runtime_v1_api)
