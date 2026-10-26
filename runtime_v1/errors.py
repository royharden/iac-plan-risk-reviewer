"""Refusals for the offline runtime-v1 construction edition."""


class Denied(RuntimeError):
    pass


class Unknown(Denied):
    pass


class ActualTrustUnavailable(Denied):
    pass


class ActualObserverUnavailable(Denied):
    pass
