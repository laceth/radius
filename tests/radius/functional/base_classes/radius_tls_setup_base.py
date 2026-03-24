"""
TLS version enforcement mixins for TC-9505 – TC-9512.

These three classes handle the Windows Schannel registry change and the
idempotent reboot — nothing else.  All test logic (_*AuthDoTest classes and
constants) lives in ``radius_functional_tls_version.py``.

Lifecycle
---------
* ``do_setup``      — calls ``ensure_windows_tls_version`` (idempotent reboot).
* ``suite_teardown``— calls ``restore_windows_tls_defaults`` automatically once
                      after the full suite completes, removing all TLS registry
                      keys and rebooting so the endpoint returns to OS defaults.
"""
from framework.log.logger import log
from tests.radius.radius_test_base import RadiusTestBase


class _VersionSkipped(RuntimeError):
    """Raised when the product version does not support legacy TLS enforcement."""


class _TLSSetup(RadiusTestBase):
    """
    Ensures Windows Schannel is restricted to exactly one TLS version before
    each test's ``do_setup`` runs.  Idempotent: reads a marker file on the
    Windows endpoint and only reboots when the current version differs.
    """

    TLS_VERSION:    str  # e.g. "1.0"
    RADIUS_MIN_TLS: str  # e.g. "v1_0"

    def do_setup(self):
        # Check product version — TLS 1.0/1.1 enforcement is only supported on 8.x.
        ca_version = self.ca.get_version_ca()
        major = int(ca_version.split(".")[0])
        if major >= 9:
            log.info(
                f"Skipping TLS {self.TLS_VERSION} tests: product version {ca_version} does not support legacy TLS enforcement (requires 8.x)."
            )
            return
        super().do_setup()
        self.configure_radius_settings(minimum_tls_version=self.RADIUS_MIN_TLS)
        self.passthrough.ensure_windows_tls_version(self.TLS_VERSION)
        self.passthrough.ensure_auto_logon()
        if self.passthrough.need_reboot():
            self.passthrough.trigger_reboot()

    def suite_teardown(self):
        super().suite_teardown()
        log.info("[TLSSetup] Restoring Windows Schannel TLS defaults after suite...")
        try:
            self.passthrough.restore_windows_tls_defaults()
        except Exception as e:
            log.error(f"[TLSSetup] Failed to restore Windows TLS defaults: {e}")


class _TLS10Setup(_TLSSetup):
    """Restricts Windows Schannel to TLS 1.0 only."""
    TLS_VERSION    = "1.0"
    RADIUS_MIN_TLS = "v1_0"


class _TLS11Setup(_TLSSetup):
    """Restricts Windows Schannel to TLS 1.1 only."""
    TLS_VERSION    = "1.1"
    RADIUS_MIN_TLS = "v1_1"
