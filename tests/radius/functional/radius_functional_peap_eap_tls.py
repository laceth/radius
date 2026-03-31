from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, WindowsCert
from lib.passthrough.lan_profile_builder import LanProfile
from lib.plugin.radius.enums import PreAdmissionAuth, RadiusFragmentSize
from framework.decorator.prametrizor import parametrize
from tests.radius.functional.base_classes.radius_eap_tls_test_base import RadiusEapTlsTestBase
from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase
from tests.radius.functional.base_classes.radius_peap_eap_tls_test_base import RadiusPeapEapTlsTestBase

RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]
RULE_EAP_TYPE_PEAP = [{"rule_name": "EAP-Type", "fields": ["PEAP"]}]
CERT_PASSWORD = "aristo"

class PEAPEAPTLSBasicAuthWiredTest(RadiusPeapEapTlsTestBase):
    """
     TC-9307 (T1316930)
    Steps
    -----
     1. In CounterAct go to Options -> Radius -> Pre-admission Authorization,
         add a rule **EAP-Type = PEAP**, apply, and verify the rule is saved
         with priority 1 and the Radius plugin restarts.
    2. Disconnect/reconnect the host NIC and verify it receives an IP address from the configured VLAN (ipconfig).
     3. On the Home tab open the host **Profile -> Authentication** header
         and verify Pre-Admission rule 1 is used and the RADIUS
         Authentication State is **RADIUS-Accepted** (PEAP-EAP-TLS).

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
        try:
            self.configure_lan_profile(lan_profile=LanProfile.peap_eap_tls())
            self.dot1x.set_pre_admission_rules(self.SET_BASIC_ACCEPT_PEAP_EAP_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_VALID.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1["interface"])
            self.verify_authentication_on_ca()
        except Exception as e:
            log.error(f"[T1316930] FAIL: {e}")
            raise

class PEAPEAPTLSRegexpPreAdmissionTest(RadiusPeapEapTlsTestBase):
    """
    TC-9286 (C143274)
    DOT | Verify Host authentication using regexp pre authentication rule PEAP-EAP-TLS (wired)

    Steps
    -----
    1. Add pre-admission rule: User-Name -> Matches Expression -> host/(.*)
       Apply configuration, verify rule saved with priority 1, RADIUS plugin restarts.
    2. Disconnect/reconnect the host NIC, verify it receives an IP from the configured VLAN.
    3. Verify authentication details on CounterAct:
       - 802.1x Authorization Source: Pre-Admission rule 1
       - 802.1x RADIUS Authentication State: RADIUS-Accepted
       - 802.1x Authenticated Entity: Computer
       - 802.1x Authentication type: PEAP-EAP-TLS
    """

    RULE_USER_NAME_MATCHES_HOST_REGEXP = [{"criterion_name": "User-Name", "criterion_value": ["matchesexpression", "host/(.*)"]}]

    SET_USERNAME_HOST_REGEXP_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_USER_NAME_MATCHES_HOST_REGEXP, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        try:
            self.configure_lan_profile(lan_profile=LanProfile.peap_eap_tls())
            self.dot1x.set_pre_admission_rules(self.SET_USERNAME_HOST_REGEXP_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_G.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1["interface"])
            self.verify_authentication_on_ca()
        except Exception as e:
            log.error(f"[TC-9286] FAIL: {e}")
            raise

# ===================================================================================
# TC-9294 — PEAP-EAP-TLS:  setting the Fragment size (Framed-MTU = Fragment size - 30)
# =====================================================================================
@parametrize(
    "fragment_size",
    [
        (RadiusFragmentSize.SIZE_1024.name,),   # T1316989 TC-9294
        (RadiusFragmentSize.SIZE_1400.name,),   # T1316991 TC-9295
        (RadiusFragmentSize.SIZE_1230.name,),   # T1316992 TC-9296
        (RadiusFragmentSize.SIZE_500.name,),    # T1316993 TC-9297
    ],
)
class TC_9294_RadiusFragmentSizeDefaultWiredPeapEapTls(RadiusPeapEapTlsTestBase):
    """
     TC-9294/TC-9295/TC-9296/TC-9297

    DOT | Verify setting the Fragment size (Framed-MTU = Fragment size - 30)

    Steps (TestRail):
    -----
    1. Options -> Radius -> Radius Settings: Set Fragment size to <fragment_size>, Apply.
    2. Options -> Radius -> Pre-Admission Authorization:
       - Add rule: EAP-Type = PEAP
       - Add rule: EAP-Type = EAP-TLS
    3. Authenticate using PEAP-EAP-TLS and verify authenticated (rule 1).
    4. Authenticate using EAP-TLS and verify authenticated (rule 2).
    5. Authenticate using PEAP and verify authenticated (rule 1).
    """

    RULE_EAP_TYPE_PEAP = [{"criterion_name": "EAP-Type", "criterion_value": ["PEAP"]}]
    RULE_EAP_TYPE_EAP_TLS = [{"criterion_name": "EAP-Type", "criterion_value": ["EAP-TLS"]}]
    RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]

    def do_test(self):
        try:
            fragment_size = RadiusFragmentSize[self.test_params["fragment_size"]].value
            # Step 1: Configure fragment size in RADIUS plugin
            self.configure_radius_settings(
                fragment_size=fragment_size,
            )

            # Step 2: Configure Pre-Admission rules (PEAP + EAP-TLS, else deny)
            set_rules = [
                {"cond_rules": self.RULE_EAP_TYPE_PEAP, "auth": PreAdmissionAuth.ACCEPT},  # priority 1
                {"cond_rules": self.RULE_EAP_TYPE_EAP_TLS, "auth": PreAdmissionAuth.ACCEPT},  # priority 2
                {"cond_rules": self.RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
            ]
            self.dot1x.set_pre_admission_rules(set_rules)
            self.certificate_password = CERT_PASSWORD
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_VALID.value
            self.import_certificates(certificate_password=self.certificate_password)

            # Step 3: PEAP-EAP-TLS (outer is PEAP -> rule priority 1)
            self.configure_lan_profile(lan_profile=LanProfile.peap_eap_tls())
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1["interface"])
            self.verify_authentication_on_ca()
            self.verify_radius_get_log(fragment_size=fragment_size, fallback_to_appliance=True)

        except Exception as e:
            log.error(f"{self.testCaseId}  FAIL: {e}")
            raise

