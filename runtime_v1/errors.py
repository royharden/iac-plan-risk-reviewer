"""Refusals for the offline runtime-v1 construction edition."""

STOP_REASONS = frozenset(('pre-receipt-failure', 'post-receipt-failure',
                          'adapter-input-failure', 'protocol-failure'))


def sanitized_stop_reason(reason):
    """Never stringify caller input into retained failure metadata."""
    return reason if type(reason) is str and reason in STOP_REASONS else 'protocol-failure'


class Denied(RuntimeError):
    pass


class Unknown(Denied):
    pass


class ActualTrustUnavailable(Denied):
    pass


class ActualObserverUnavailable(Denied):
    pass
