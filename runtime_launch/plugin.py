"""Explicit inert collection/result integration; refuses pytest test bodies."""

from .adapter import InertSession
from runtime_v1.errors import Denied


class InertPlugin:
    def __init__(self, session):
        if type(session) is not InertSession:
            raise Denied("exact inert session required")
        self._session = session

    def pytest_collection_finish(self, session):
        self._session.validate_collection([item.nodeid for item in session.items])

    def pytest_runtest_protocol(self, item, nextitem):
        # Collecting DATA must never cause a real original test body to execute.
        self._session.stop()
        raise Denied("inert plugin does not execute original bodies")

    def record(self, nodeid, status):
        self._session.record_result(nodeid, status)

    def complete(self):
        return self._session.complete()
