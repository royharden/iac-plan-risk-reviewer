"""One API-derived logical family, authored before any D8 code inspection.

The injection seam is provisional until static source mapping. It changes only
an inert clock-provider identity fact, never real time, threads or a clock call.
The adapter must not implement source identity checks or poisoning itself.
"""
from protocol_suite import bound, refused


def clock_identity_tamper_entry_audit_exit_persistent_poison(api):
    for stage in ('entry', 'audit', 'exit'):
        data, context = bound(api, kind='junction')
        changed_identity = object()

        def attempt():
            if stage == 'entry':
                api.set_clock_identity(context, changed_identity)
            with context.effect_window(data['slot'], data['call'], data['prehash']):
                if stage == 'audit':
                    api.set_clock_identity(context, changed_identity)
                context.audit_inert(data['event'], data['audit_args'])
                if stage == 'exit':
                    api.set_clock_identity(context, changed_identity)

        refused(api.Denied, attempt)
        assert api.inspect(context)['poisoned'] is True
        refused(api.Denied, context.require_exact)


CASES = [clock_identity_tamper_entry_audit_exit_persistent_poison]
