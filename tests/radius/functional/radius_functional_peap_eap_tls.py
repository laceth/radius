from dataclasses import field
from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile, WindowsCert
from lib.plugin.radius.enums import Dot1xAttribute, PreAdmissionAuth, MscaOid, EKUEntry, MSCAEntry
from tests.radius.functional.base_classes.radius_peap_eap_tls_test_base import RadiusPeapEapTlsTestBase
from lib.utils.vlan_mapping import get_vlan_from_ip, get_ip_range_from_vlan


RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]
RULE_EAP_TYPE_PEAP = [{"rule_name": "EAP-Type", "fields": ["PEAP"]}]
CERT_PASSWORD = "aristo"

class PEAPEAPTLSBasicAuthWiredTest(RadiusPeapEapTlsTestBase):
    """
    T1316930 same as T1316929 (Wireless)
    Steps
    -----
    1. In CounterAct go to Options -> Radius -> Pre-admission Authorization, add a rule **EAP-Type = PEAP**, apply, and verify the rule is saved with priority 1 and the Radius plugin restarts.
    2. Disconnect/reconnect the host NIC and verify it receives an IP address from the configured VLAN (ipconfig).
    3. On the Home tab open the host **Profile -> Authentication** header and verify Pre-Admission rule 1 is used and the RADIUS Authentication State is **RADIUS-Accepted** (PEAP-EAP-TLS).

    """


    SET_BASIC_ACCEPT_PEAP_EAP_ELSE_DENY = [
        {
            "cond_rules": RULE_EAP_TYPE_PEAP,
            "auth": PreAdmissionAuth.ACCEPT,
        },
        {
            "cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS,
            "auth": PreAdmissionAuth.REJECT_DUMMY,
        },
    ]

    def do_test(self):
        auth_nic_profile = AuthNicProfile.PEAP_EAP_TLS
        expected_status = AuthenticationStatus.SUCCEEDED
        self.certificate_password = CERT_PASSWORD
        case_id = "T1316930"

        try:
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)
            self.dot1x.set_pre_admission_rules(self.SET_BASIC_ACCEPT_PEAP_EAP_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_VALID.value
            self.import_certificates(certificate_password=self.certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            self.wait_for_nic_ip_in_range()
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca()
        except Exception as e:
            log.error(f"[{case_id}] FAIL: {e}")
            raise


