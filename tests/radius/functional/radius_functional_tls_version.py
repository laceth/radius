"""
Legacy TLS (1.0 / 1.1) Endpoint Authentication Tests
=====================================================

  TC-9505  DOT | Verify PEAP authentication over TLS-1.0
  TC-9506  DOT | Verify PEAP-EAP-TLS authentication over TLS-1.0
  TC-9507  DOT | Verify EAP-TLS authentication over TLS-1.0
  TC-9508  DOT | Verify EAP-TTLS authentication over TLS-1.0
  TC-9509  DOT | Verify PEAP authentication over TLS-1.1
  TC-9510  DOT | Verify PEAP-EAP-TLS authentication over TLS-1.1
  TC-9511  DOT | Verify EAP-TLS authentication over TLS-1.1
  TC-9512  DOT | Verify EAP-TTLS authentication over TLS-1.1

Execution order
---------------
``inspect.getmembers`` returns classes **alphabetically**, so the runner sees:
  TC_9505 → TC_9506 → TC_9507 → TC_9508 → TC_9509 → TC_9510 → TC_9511 → TC_9512

This keeps all TLS 1.0 tests together and all TLS 1.1 tests together, so
Windows reboots happen exactly **twice** across the full run:
  ┌──────────┬─────────┬──────────────────────────────────────┐
  │ Test     │ TLS ver │ ensure_windows_tls_version result     │
  ├──────────┼─────────┼──────────────────────────────────────┤
  │ TC_9505  │ 1.0     │ marker=default → reboot ①            │
  │ TC_9506  │ 1.0     │ marker=1.0     → skip                │
  │ TC_9507  │ 1.0     │ marker=1.0     → skip                │
  │ TC_9508  │ 1.0     │ marker=1.0     → skip                │
  │ TC_9509  │ 1.1     │ marker=1.0     → reboot ②            │
  │ TC_9510  │ 1.1     │ marker=1.1     → skip                │
  │ TC_9511  │ 1.1     │ marker=1.1     → skip                │
  │ TC_9512  │ 1.1     │ marker=1.1     → skip                │
  └──────────┴─────────┴──────────────────────────────────────┘

After the full suite completes, ``suite_teardown`` in ``_TLSSetup`` automatically
calls ``restore_windows_tls_defaults()``, removing all TLS registry keys and
rebooting the endpoint back to OS defaults.
"""

from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, WindowsCert
from lib.passthrough.lan_profile_builder import LanProfile
from lib.plugin.radius.enums import PreAdmissionAuth
from tests.radius.functional.base_classes.radius_eap_tls_test_base import RadiusEapTlsTestBase
from tests.radius.functional.base_classes.radius_eap_ttls_test_base import RadiusEapTtlsTestBase
from tests.radius.functional.base_classes.radius_peap_eap_tls_test_base import RadiusPeapEapTlsTestBase
from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase
from tests.radius.functional.base_classes.radius_tls_setup_base import _TLS10Setup, _TLS11Setup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CERT_PASSWORD    = "aristo"
DOMAIN           = "txqalab"
USER_RHUGHES_ADM = "rhughes-adm"

# Pre-admission rules
COND_EAP_TYPE_PEAP    = [{"criterion_name": "EAP-Type", "criterion_value": ["PEAP"]}]
COND_EAP_TYPE_TLS     = [{"criterion_name": "EAP-Type", "criterion_value": ["TLS"]}]
COND_EAP_TYPE_EAPTTLS = [{"criterion_name": "EAP-Type", "criterion_value": ["EAP-TTLS"]}]

RULES_ACCEPT_EAP_TYPES = [
    {"cond_rules": COND_EAP_TYPE_PEAP,    "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": COND_EAP_TYPE_TLS,     "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": COND_EAP_TYPE_EAPTTLS, "auth": PreAdmissionAuth.ACCEPT},
]

# (inner_method_label, LanProfile factory, username — None means cert-based)
EAP_TTLS_VARIANTS = [
    ("eap_mschapv2", LanProfile.eap_ttls_eap_mschapv2, USER_RHUGHES_ADM),
    ("eap_cert",     LanProfile.eap_ttls_eap_cert,     None),
]


# ---------------------------------------------------------------------------
# Shared do_test classes — one per EAP auth type
# ---------------------------------------------------------------------------

class _PEAPAuthentication(RadiusPeapTestBase):
    """Shared ``do_test`` for PEAP over a legacy TLS version (TC-9505 / TC-9509)."""

    def do_test(self):
        try:
            tls_pattern = f'TLS-Session-Version = "TLS {self.TLS_VERSION}"'
            self.configure_radius_settings(minimum_tls_version=self.RADIUS_MIN_TLS)
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_EAP_TYPES)
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            self.setup_peap_credentials(DOMAIN, USER_RHUGHES_ADM)
            self.wait_for_dot1x_ready()
            tls_watcher = self.radiusd_log_collector.start_log_check([f'(?i){tls_pattern}'])
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_authentication_on_ca()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties()
            found, matched = self.radiusd_log_collector.get_log_check_result(tls_watcher)
            assert found, f'{tls_pattern} not found in radiusd.log'
            log.info(f"[radiusd] {tls_pattern} — matched: { {k + 1: v for k, v in matched.items()} }")
        except Exception as e:
            log.error(f"[{self.__class__.__name__}] failed: {e}")
            raise


class _PEAPEAPTLSAuthentication(RadiusPeapEapTlsTestBase):
    """Shared ``do_test`` for PEAP-EAP-TLS over a legacy TLS version (TC-9506 / TC-9510)."""

    def do_test(self):
        try:
            tls_pattern = f'TLS-Session-Version = "TLS {self.TLS_VERSION}"'
            self.configure_radius_settings(minimum_tls_version=self.RADIUS_MIN_TLS, fragment_size="1114")
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_EAP_TYPES)
            self.configure_lan_profile(lan_profile=LanProfile.peap_eap_tls())
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_VALID.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            tls_watcher = self.radiusd_log_collector.start_log_check([f'(?i){tls_pattern}'])
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_authentication_on_ca()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties()
            found, matched = self.radiusd_log_collector.get_log_check_result(tls_watcher)
            assert found, f'{tls_pattern} not found in radiusd.log'
            log.info(f"[radiusd] {tls_pattern} — matched: { {k + 1: v for k, v in matched.items()} }")
        except Exception as e:
            log.error(f"[{self.__class__.__name__}] failed: {e}")
            raise


class _EAPTLSAuthentication(RadiusEapTlsTestBase):
    """Shared ``do_test`` for EAP-TLS over a legacy TLS version (TC-9507 / TC-9511)."""

    def do_test(self):
        try:
            tls_pattern = f'TLS-Session-Version = "TLS {self.TLS_VERSION}"'
            self.configure_radius_settings(minimum_tls_version=self.RADIUS_MIN_TLS)
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_EAP_TYPES)
            self.configure_lan_profile(lan_profile=LanProfile.eap_tls())
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_G.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            tls_watcher = self.radiusd_log_collector.start_log_check([f'(?i){tls_pattern}'])
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_authentication_on_ca()
            self.verify_pre_admission_rule(rule_priority=2)
            self.verify_wired_properties()
            found, matched = self.radiusd_log_collector.get_log_check_result(tls_watcher)
            assert found, f'{tls_pattern} not found in radiusd.log'
            log.info(f"[radiusd] {tls_pattern} — matched: { {k + 1: v for k, v in matched.items()} }")
        except Exception as e:
            log.error(f"[{self.__class__.__name__}] failed: {e}")
            raise


class _EAPTTLSAuthentication(RadiusEapTtlsTestBase):
    """
    Shared ``do_test`` for EAP-TTLS over a legacy TLS version (TC-9508 / TC-9512).
    Tests both inner methods (MSCHAPv2 and cert-based) in sequence.
    """

    def do_test(self):
        try:
            tls_pattern = f'TLS-Session-Version = "TLS {self.TLS_VERSION}"'
            self.configure_radius_settings(minimum_tls_version=self.RADIUS_MIN_TLS)
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_EAP_TYPES)
            for inner_method, profile_factory, username in EAP_TTLS_VARIANTS:
                log.info(f"[{self.__class__.__name__}] EAP-TTLS inner method: {inner_method}")
                self.configure_lan_profile(lan_profile=profile_factory())
                if username:
                    self.setup_eap_ttls_credentials(DOMAIN, username)
                self.wait_for_dot1x_ready()
                tls_watcher = self.radiusd_log_collector.start_log_check([f'(?i){tls_pattern}'])
                self.toggle_nic()
                self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
                self.verify_nic_ip_in_range()
                self.verify_authentication_on_ca(inner_method=inner_method)
                self.verify_pre_admission_rule(rule_priority=3)
                self.verify_wired_properties()
                found, matched = self.radiusd_log_collector.get_log_check_result(tls_watcher)
                assert found, f'{tls_pattern} not found in radiusd.log'
                log.info(f"[radiusd] {tls_pattern} — matched: { {k + 1: v for k, v in matched.items()} }")
        except Exception as e:
            log.error(f"[{self.__class__.__name__}] failed: {e}")
            raise

# ===========================================================================
# TLS 1.0 — TC-9505 … TC-9508  (Windows reboots once, on TC-9505)
# ===========================================================================

class TC_9505_PEAPOverTLS10(_TLS10Setup, _PEAPAuthentication):
    """TC-9505: DOT | Verify PEAP authentication over TLS-1.0"""
    configure_radius_settings_in_test = True


class TC_9506_PEAPEAPTLSOverTLS10(_TLS10Setup, _PEAPEAPTLSAuthentication):
    """TC-9506: DOT | Verify PEAP-EAP-TLS authentication over TLS-1.0"""
    configure_radius_settings_in_test = True


class TC_9507_EAPTLSOverTLS10(_TLS10Setup, _EAPTLSAuthentication):
    """TC-9507: DOT | Verify EAP-TLS authentication over TLS-1.0"""
    configure_radius_settings_in_test = True


class TC_9508_EAPTTLSOverTLS10(_TLS10Setup, _EAPTTLSAuthentication):
    """TC-9508: DOT | Verify EAP-TTLS authentication over TLS-1.0"""
    configure_radius_settings_in_test = True


# ===========================================================================
# TLS 1.1 — TC-9509 … TC-9512  (Windows reboots once, on TC-9509)
# ===========================================================================

class TC_9509_PEAPOverTLS11(_TLS11Setup, _PEAPAuthentication):
    """TC-9509: DOT | Verify PEAP authentication over TLS-1.1"""
    configure_radius_settings_in_test = True


class TC_9510_PEAPEAPTLSOverTLS11(_TLS11Setup, _PEAPEAPTLSAuthentication):
    """TC-9510: DOT | Verify PEAP-EAP-TLS authentication over TLS-1.1"""
    configure_radius_settings_in_test = True


class TC_9511_EAPTLSOverTLS11(_TLS11Setup, _EAPTLSAuthentication):
    """TC-9511: DOT | Verify EAP-TLS authentication over TLS-1.1"""
    configure_radius_settings_in_test = True


class TC_9512_EAPTTLSOverTLS11(_TLS11Setup, _EAPTTLSAuthentication):
    """TC-9512: DOT | Verify EAP-TTLS authentication over TLS-1.1"""
    configure_radius_settings_in_test = True
