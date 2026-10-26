"""Synthetic state interpreter; no filesystem/device observer is installed."""
from copy import deepcopy

from .errors import ActualObserverUnavailable, Denied, Unknown
from .runtime_manifest import closed, exact_value, need


def observe_original(*args, **kwargs):
    raise ActualObserverUnavailable('actual observer is uninstalled')


def observe_inert(pending, relation, result, error, state):
    try:
        need(type(pending) is dict and pending.get('seen') is True, 'pending event correlation missing')
        need(exact_value(relation, pending['relation']), 'pending relation changed')
        closed(state, 'known ordinary target_identity link_kind link_target child_terminated')
        need(state['known'] is True and state['ordinary'] is True, 'unknown ownership/state')
        need(exact_value(state['target_identity'], relation['target_identity']), 'target identity changed')
        need(state['child_terminated'] is True, 'uncertain child termination')
        # A known original failure may leave no link or the exact expected link.
        if state['link_kind'] == 'absent':
            need(error is not None and state['link_target'] is None, 'unexpected absence after success')
        else:
            need(exact_value(state['link_kind'], pending['slot']['kind'])
                 and exact_value(state['link_target'], relation['target']), 'unexpected link state')
        return {'known': True, 'synthetic': True, 'actual_link_verified': False,
                'state': deepcopy(state), 'pre_sha256': pending['pre_sha256']}
    except (Denied, KeyError, TypeError) as exc:
        unknown = Unknown('synthetic observation UNKNOWN')
        raise unknown from (error if error is not None else exc)
