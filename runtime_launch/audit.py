"""Controlled audit routing DATA. No hook is installed by this module."""

from runtime_v1.errors import ActualTrustUnavailable, Denied

_CONTROLLED = frozenset({"os.symlink", "subprocess.Popen"})
_DENIED = frozenset({
    "os.remove", "os.rmdir", "shutil.rmtree", "os.rename", "os.link",
    "os.system", "os.startfile", "os.startfile/2", "os.fork", "os.forkpty",
    "os.posix_spawn", "os.truncate", "os.chmod", "os.chown",
})


class AuditRouter:
    """Dormant delegate preserves the core's exact audit window checks.

    The supplied object is an injected test dependency or an already-issued
    context; it is never authority to install or run anything. Arbitrary method
    calls are trusted code in this cooperative seam, not sandbox evidence.
    """

    def __init__(self, context):
        if not callable(getattr(context, "audit", None)):
            raise Denied("audit interface required")
        self._context = context
        self._blocked = False

    @property
    def blocked(self):
        return self._blocked

    def audit(self, event, args):
        try:
            if self._blocked or type(event) is not str or type(args) is not tuple:
                raise Denied("audit routing blocked or malformed")
            if event in _CONTROLLED:
                self._context.audit(event, args)
            elif (event in _DENIED or event.startswith(("socket.", "os.exec", "os.spawn",
                                                       "ctypes.", "winreg.", "_winapi."))):
                raise Denied("event outside exact controlled windows")
        except BaseException:
            self._blocked = True
            raise

    def install(self):
        # An injected audit callback must never install a global OS hook or
        # activate originals. Actual qualification remains an external edge.
        self._blocked = True
        raise ActualTrustUnavailable("operational audit installation is not admitted")
