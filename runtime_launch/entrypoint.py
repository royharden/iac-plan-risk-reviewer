"""Fail-closed command entry. Runtime preparation and original103 remain held."""

import json
import sys


def main(argv=None):
    """No CLI argument/environment value is an activation capability.

    No pytest import, audit-hook installation, metadata observer, namespace or
    output-file write occurs on this path. Reasons deliberately omit input.
    """
    arguments = sys.argv[1:] if argv is None else argv
    if type(arguments) is not list or arguments:
        reason = "ACTIVATION_ARGUMENTS_NOT_ACCEPTED"
    else:
        from runtime_v1.errors import ActualTrustUnavailable
        from runtime_v1.guarded_context import load_actual_context

        try:
            load_actual_context()
        except ActualTrustUnavailable:
            reason = "INDEPENDENT_ROOT_ADMISSION_UNAVAILABLE"
        else:
            # Issuance alone cannot silently grant the still-unadmitted original
            # runner/namespace/OS qualification. No supplied context is used.
            reason = "ORIGINAL_RUNNER_PREFLIGHT_NOT_ADMITTED"
    print(json.dumps({
        "status": "REFUSED",
        "code": reason,
        "test_bodies_executed": 0,
        "native_dispatches": 0,
        "actual_runtime_verified": False,
        "full103_green": False,
    }, sort_keys=True))
    return 2
