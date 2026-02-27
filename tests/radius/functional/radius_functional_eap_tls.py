from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, WindowsCert
from lib.passthrough.lan_profile_builder import LanProfile
from lib.plugin.radius.enums import Dot1xAttribute, PreAdmissionAuth, MscaOid, EKUEntry, MSCAEntry, RadiusAuthStatus
from tests.radius.functional.base_classes.radius_eap_tls_test_base import RadiusEapTlsTestBase


DOT1X_CLIENT_CERT_VALID = getattr(WindowsCert, "DOT1X_CLT_RADIUS_SET1", WindowsCert.CERT_DOT1X_VALID)
DOT1X_CLIENT_CERT_REVOKED = getattr(WindowsCert, "DOT1X_CLT_RADIUS_SET2", WindowsCert.CERT_DOT1X_REVOKED)

CERT_PASSWORD = "aristo"

RULE_EAP_TYPE_TLS = [{"criterion_name": "EAP-Type", "criterion_value": ["TLS"]}]
RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]
EXPECTED_SAN = "URI:E2EQADeviceId://qae2e-san-testid-12345"


class EAPTLSPreAdmissionSANTest(RadiusEapTlsTestBase):
    """
    T1316924
    Steps
    -------
    1. Configure pre-admission rule: Certificate-From-Subject Alternative-Name CONTAINS "san-test" (priority 1).
    2. Add column "802.1x Client Cert Subject Alternative Name" to the ALL Host table.
    3. Disconnect/reconnect the Windows NIC to trigger 802.1x and obtain an IP from the configured VLAN.
    4. Verify the ALL Host table SAN column shows the SAN value from the client certificate (e.g., URL=E2EQADeviceId:/qae2e-san-testid-12345).
    5. On the host Profile -> Authentication header, verify: Pre-Admission rule 1, RADIUS-Accepted, EAP-TLS.
    """

    # Rule Settings
    RULE_USER_NAME_ANY = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]
    RULE_SAN_CONTAINS_SAN_TESTID = [
        {"criterion_name": Dot1xAttribute.CERT_FROM_SUBJECT_ALTERNATIVE_NAME.value, "criterion_value": ["contains", "san-testid"]}
    ]

    SET_SAN_CONTAINS_EXPECTED_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_SAN_CONTAINS_SAN_TESTID, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        try:
            self.configure_lan_profile(lan_profile=LanProfile.eap_tls())
            self.dot1x.set_pre_admission_rules(self.SET_SAN_CONTAINS_EXPECTED_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_Client_SAN.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()
            self.verify_san(expected_san=EXPECTED_SA)
        except Exception as e:
            log.error(f"[T1316924] FAIL: {e}")
            raise

class EAPTLSPolicySANDetectionTest(RadiusEapTlsTestBase):
    """
    T1316925
    Steps
    -----
    1. Create Custom policy "Radius SAN" with condition:
       802.1x Client Cert Subject Alternative Name CONTAINS "san-testid"
       Apply and verify it matches the host.
    2. Edit policy: change condition to CONTAINS "invalid"
       Apply and verify host no longer matches.
    3. Edit policy back to CONTAINS "san-testid"
       Apply and verify host matches again.
    """

    SET_ACCEPT_TLS_ELSE_DENY = [
        {"cond_rules": RULE_EAP_TYPE_TLS, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    EXPECTED_SAN = "URI:E2EQADeviceId://qae2e-san-testid-12345"

    def do_test(self):
        try:
            # --- Preconditions: endpoint authenticates via EAP-TLS ---
            self.configure_lan_profile(lan_profile=LanProfile.eap_tls())
            self.cert_config.certificate_filename = WindowsCert.CERT_Client_SAN.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.dot1x.set_pre_admission_rules(self.SET_ACCEPT_TLS_ELSE_DENY)
            
            # Admission #1: create/update endpoint and populate properties (including SAN)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.wait_for_nic_ip_in_range()
            self.verify_wired_properties(nas_port_id=self.switch.port1["interface"])
            
            # Validate SAN is present on the endpoint (good sanity check)
            self.verify_san(expected_san=self.EXPECTED_SAN)
            # ---------- Step 1: Policy contains "san-testid" ----------
            policy_name = self.add_dot1x_policy_radius_fr_client_x509_cert_subj_alt_name(
                match_type="contains",
                value="san-testid",
                match_case=False,
            )
            # Admission #2: force policy evaluation after policy import/update
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.wait_for_nic_ip_in_range()
            self.verify_wired_properties(nas_port_id=self.switch.port1["interface"])
            self.verify_policy_match(policy_name, expected_count=1)
                        
            # ---------- Step 2: Update policy to contains "invalid" ----------
            policy_name = self.add_dot1x_policy_radius_fr_client_x509_cert_subj_alt_name(
                match_type="contains",
                value="invalid",
                match_case=False,
            )
            # Admission #3: force re-eval after update
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.wait_for_nic_ip_in_range()
            self.verify_wired_properties(nas_port_id=self.switch.port1["interface"])
            self.verify_policy_match(policy_name, expected_count=0)
            
            # ---------- Step 3: Revert policy back to contains "san-testid" ----------
            policy_name = self.add_dot1x_policy_radius_fr_client_x509_cert_subj_alt_name(
                match_type="contains",
                value="san-testid",
                match_case=False,
            )
            # Admission #4: force re-eval after revert
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.wait_for_nic_ip_in_range()
            self.verify_wired_properties(nas_port_id=self.switch.port1["interface"])
            self.verify_policy_match(policy_name, expected_count=1)
            
        except Exception as e:
            log.error(f"[T1316925] FAIL: {e}")
            raise

class EAPTLSBasicAuthWiredTest(RadiusEapTlsTestBase):
    """
    T1316931 same as T1316932 (Wireless)
    Steps
    -----
    1. In CounterAct go to Options -> Radius -> Pre-admission Authorization, add a rule **EAP-Type = TLS**, apply, and verify the rule is saved with priority 1 and the Radius plugin restarts.
    2. Disconnect/reconnect the host NIC and verify it receives an IP address from the configured VLAN (ipconfig).
    3. On the Home tab open the host **Profile -> Authentication** header and verify Pre-Admission rule 1 is used and the RADIUS Authentication State is **RADIUS-Accepted** (EAP-TLS).
    4. On the host use MMC to move the CA cert from **Trusted Root Certification Authorities** to **Personal**, reconnect the NIC, and verify the Authentication header shows **RADIUS-Rejected** and the NIC no longer has an IP address.
    """


    SET_BASIC_WIRED_ACCEPT_TLS_ELSE_DENY = [
        {
            "cond_rules": RULE_EAP_TYPE_TLS,
            "auth": PreAdmissionAuth.ACCEPT,
        },
        {
            "cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS,
            "auth": PreAdmissionAuth.REJECT_DUMMY,
        },
    ]

    def do_test(self):
        try:
            self.configure_lan_profile(lan_profile=LanProfile.eap_tls())
            self.dot1x.set_pre_admission_rules(self.SET_BASIC_WIRED_ACCEPT_TLS_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_G.value
            self.import_certificates(certificate_password=CERT_PASSWORD)

            # Step 2-3: Toggle NIC and verify successful authentication
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            # Step 4: Move CA cert from Trusted Root to Personal and verify RADIUS-Rejected
            self.move_ca_cert_to_personal_store()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.FAILED)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT)
            # Verify NIC no longer has an IP address in the configured VLAN range
            self.verify_nic_has_no_ip_in_range()

        except Exception as e:
            log.error(f"[T1316931] FAIL: {e}")
            raise

class EAPTLSPreAdmissionMSCATemplateTest(RadiusEapTlsTestBase):
    """
    T1316960
    Certificate-EAP-TLS-Template / OID

    Steps
    -------
    1. Configure LAN profile on the host for EAP-TLS.
    2. Import client certificate TEMPLATE_CON_CERT on the host.
    3. Configure pre-admission rule: Certificate-EAP-TLS-Certificate-Template MATCHES template OID (priority 1).
       Trigger 802.1X. Verify RADIUS-Accepted / Pre-Admission rule 1 matched (EAP-TLS).
    4. Update rule 1: Certificate-EAP-TLS-Certificate-Template MATCHES invalid OID. Apply.
       Trigger 802.1X. Verify authentication FAILED (dummy reject matched).
    5. Update rule 1: Certificate-EAP-TLS-Certificate-Template ANYVALUE. Apply.
       Trigger 802.1X. Verify RADIUS-Accepted / rule 1 matched.
    6. Update rule 1: Certificate-EAP-TLS-Certificate-Template MATCHES REGEX. Apply.
       Trigger 802.1X. Verify RADIUS-Accepted / rule 1 matched.
    7. Update rule 1: Certificate-EAP-TLS-Certificate-Template STARTSWITH OID PREFIX. Apply.
    8. Update rule 1: Certificate-EAP-TLS-Certificate-Template ENDSWITH OID SUFFIX. Apply.
    """
    TEMPLATE_OID = MscaOid.TEMPLATE_OID_01.value
    TEMPLATE_OID_PREFIX = ".".join(TEMPLATE_OID.split(".")[:10])   # stable prefix
    TEMPLATE_OID_SUFFIX = ".".join(TEMPLATE_OID.split(".")[-2:])   # stable suffix

    # Rule Settings
    RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]

    RULE_TEMPLATE_OID_MATCH = [
        {"criterion_name": Dot1xAttribute.CERT_EAP_TLS_TEMPLATE.value, "criterion_value": ["matches", MscaOid.TEMPLATE_OID_01.value]}
    ]
    RULE_TEMPLATE_OID_INVALID_MATCH = [
        {"criterion_name": Dot1xAttribute.CERT_EAP_TLS_TEMPLATE.value, "criterion_value": ["matches", "INVALID_OID_VALUE"]}
    ]
    RULE_TEMPLATE_OID_ANYVALUE = [{"criterion_name": Dot1xAttribute.CERT_EAP_TLS_TEMPLATE.value, "criterion_value": ["anyvalue"]}]
    RULE_TEMPLATE_OID_REGEX_MATCH = [
        {
            "criterion_name": Dot1xAttribute.CERT_EAP_TLS_TEMPLATE.value,
            "criterion_value": ["matchesexpression", MscaOid.TEMPLATE_OID_02_REGEX.value],
        }
    ]

    RULE_TEMPLATE_OID_STARTSWITH = [
    {"criterion_name": Dot1xAttribute.CERT_EAP_TLS_TEMPLATE.value, "criterion_value": ["startswith", TEMPLATE_OID_PREFIX]}
    ]

    RULE_TEMPLATE_OID_ENDSWITH = [
        {"criterion_name": Dot1xAttribute.CERT_EAP_TLS_TEMPLATE.value, "criterion_value": ["endswith", TEMPLATE_OID_SUFFIX]}
    ]

    SET_OID_MATCH_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_TEMPLATE_OID_MATCH, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]
    SET_OID_INVALID_MATCH_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_TEMPLATE_OID_INVALID_MATCH, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]
    SET_OID_ANYVALUE_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_TEMPLATE_OID_ANYVALUE, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]
    SET_OID_REGEX_MATCH_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_TEMPLATE_OID_REGEX_MATCH, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_OID_STARTSWITH_ACCEPT_ELSE_DENY = [
    {"cond_rules": RULE_TEMPLATE_OID_STARTSWITH, "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_OID_ENDSWITH_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_TEMPLATE_OID_ENDSWITH, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        try:
            self.configure_lan_profile(lan_profile=LanProfile.eap_tls())
            # Step 2: import template client cert
            self.cert_config.certificate_filename = WindowsCert.CERT_TEMPLATE_CON_CERT.value
            self.import_certificates(certificate_password=CERT_PASSWORD)

            # Step 3: exact OID match -> ACCEPT, Rule 1 matched
            self.dot1x.set_pre_admission_rules(self.SET_OID_MATCH_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)

            # Step 4: invalid OID -> Rule 1 should NOT match, Rule 2 (REJECT) should match
            # Per CSV: "Verify the host did not match Rule One" - meaning Rule 1 doesn't match, but Rule 2 should
            self.dot1x.set_pre_admission_rules(self.SET_OID_INVALID_MATCH_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.verify_nic_has_no_ip_in_range()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.FAILED, timeout=120) #TODO: implement something instead of FAILED to verify the passthrough failure
            # Verify Rule 2 matched (the REJECT rule), not Rule 1
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT)

            # Step 5: anyvalue -> ACCEPT, Rule 1 matched
            self.dot1x.set_pre_admission_rules(self.SET_OID_ANYVALUE_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            # Step 6: regex -> ACCEPT, Rule 1 matched
            self.dot1x.set_pre_admission_rules(self.SET_OID_REGEX_MATCH_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            # Step 7: startswith OID prefix -> ACCEPT, Rule 1 matched
            self.dot1x.set_pre_admission_rules(self.SET_OID_STARTSWITH_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            # Step 8: endswith OID suffix -> ACCEPT, Rule 1 matched
            self.dot1x.set_pre_admission_rules(self.SET_OID_ENDSWITH_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()
        except Exception as e:
            log.error(f"[T1316960] FAIL: {e}")
            raise

class EAPTLSAbsurdExpiryDateTest(RadiusEapTlsTestBase):
    """
    T1316965
    Steps
    -------
    1. Configure LAN profile on the host for EAP-TLS.
    2. Configure pre-admission rule: EAP-Type = TLS (priority 1), else dummy reject.
    3. Import the client certificate with absurd expiry date (12/31/9999).
    4. Trigger 802.1X (toggle NIC). Verify RADIUS-Accepted (plugin handles absurd date gracefully).
    5. Verify plugin didn't crash by checking uptime.
    """

    # Rule Settings
    RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]
    RULE_EAP_TYPE_TLS = [{"criterion_name": "EAP-Type", "criterion_value": ["TLS"]}]

    SET_ACCEPT_TLS_ELSE_DENY = [
        {"cond_rules": RULE_EAP_TYPE_TLS, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        try:
            self.configure_lan_profile(lan_profile=LanProfile.eap_tls())
            self.dot1x.set_pre_admission_rules(self.SET_ACCEPT_TLS_ELSE_DENY)

            # Import certificate with absurd expiry date (12/31/9999)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_TIME.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()

            # Plugin should accept the cert gracefully (not crash)
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            # Verify plugin didn't crash (still running after auth)
            self.assert_dot1x_plugin_running("802.1X plugin should still be running after handling absurd expiry date")

            log.info("[T1316965] PASS - Plugin handled absurd expiry date gracefully")
        except Exception as e:
            log.error(f"[T1316965] FAIL: {e}")
            raise

class EAPTLSPreAdmissionEKUMultipleValuesTest(RadiusEapTlsTestBase):
    """
    T1316954
    Steps
    -------
    1. Disable the Windows wired NIC.
    2. In CounterAct: Options -> RADIUS -> Pre-Admission Authentication.
       Add rule 1 with condition "Certificate-Extended-Key-Usage".
       Select EKUs: .2, .4, .6, .8, .14, .16, .23, .29. Save and Apply.
    3. Enable NIC to trigger 802.1X. Verify accepted / Pre-Admission rule 1 matched (EAP-TLS).
    4. Disable NIC. Update rule 1 by deselecting EKU .2. Apply. Enable NIC. Verify accepted / rule 1 matched.
    5. Disable NIC. Update rule 1 by unselecting all but EKUs .14 and .24. Apply. Enable NIC. Verify accepted / rule 1 matched.
    6. Disable NIC. Update rule 1 by unselecting all but EKUs .14 and .29. Apply.
       Replace cert B -> cert C. Enable NIC. Verify accepted / rule 1 matched.
    7. Disable NIC. Update rule 1 by selecting ALL EKU options. Apply.
       Replace cert C -> cert D (no EKUs). Enable NIC. Verify FAIL (rule 1 not matched; dummy reject matched).
    """

    # -------------------------
    # Rule Settings
    # -------------------------
    #RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]

    RULE_EKU_CLIENT_AUTH_EMAIL_IPSEC_TIMESTAMP_EAP_SCVP_SENDROUTER_CMC = [
        {
            "criterion_name": "Certificate-Extended-Key-Usage",
            "criterion_value": [
                EKUEntry.EKU_02_CLIENT_AUTH.value,       # .2
                EKUEntry.EKU_04_EMAIL_PROTECTION.value,  # .4
                EKUEntry.EKU_06_IPSEC_TUNNEL.value,       # .6
                EKUEntry.EKU_08_TIMESTAMPING.value,       # .8
                EKUEntry.EKU_14_EAP_OVER_LAN.value,       # .14
                EKUEntry.EKU_16_SCVP_CLIENT.value,        # .16
                EKUEntry.EKU_23_SEND_ROUTER.value,        # .23
                EKUEntry.EKU_29_CMC_ARCHIVE.value,        # .29
            ],
        }
    ]

    RULE_EKU_ALL_EXCEPT_CLIENT_AUTH = [
        {
            "criterion_name": "Certificate-Extended-Key-Usage",
            "criterion_value": [
                EKUEntry.EKU_04_EMAIL_PROTECTION.value,
                EKUEntry.EKU_06_IPSEC_TUNNEL.value,
                EKUEntry.EKU_08_TIMESTAMPING.value,
                EKUEntry.EKU_14_EAP_OVER_LAN.value,
                EKUEntry.EKU_16_SCVP_CLIENT.value,
                EKUEntry.EKU_23_SEND_ROUTER.value,
                EKUEntry.EKU_29_CMC_ARCHIVE.value,
            ],
        }
    ]

    RULE_EKU_EAP_OVER_LAN_AND_SEND_PROXY = [
        {
            "criterion_name": "Certificate-Extended-Key-Usage",
            "criterion_value": [
                EKUEntry.EKU_14_EAP_OVER_LAN.value,  # .14
                EKUEntry.EKU_24_SEND_PROXY.value,    # .24
            ],
        }
    ]

    RULE_EKU_EAP_OVER_LAN_AND_CMC_ARCHIVE = [
        {
            "criterion_name": "Certificate-Extended-Key-Usage",
            "criterion_value": [
                EKUEntry.EKU_14_EAP_OVER_LAN.value,  # .14
                EKUEntry.EKU_29_CMC_ARCHIVE.value,   # .29
            ],
        }
    ]

    RULE_EKU_ALL_OPTIONS = [
        {
            "criterion_name": "Certificate-Extended-Key-Usage",
            "criterion_value": [
            EKUEntry.EKU_01_SERVER_AUTH.value,
            EKUEntry.EKU_02_CLIENT_AUTH.value,
            EKUEntry.EKU_03_CODE_SIGNING.value,
            EKUEntry.EKU_04_EMAIL_PROTECTION.value,
            EKUEntry.EKU_05_IPSEC_IKE.value,
            EKUEntry.EKU_06_IPSEC_TUNNEL.value,
            EKUEntry.EKU_07_IPSEC_USER.value,
            EKUEntry.EKU_08_TIMESTAMPING.value,
            EKUEntry.EKU_09_OCSP_SIGNING.value,
            EKUEntry.EKU_10_SSH_AUTHENTICATION.value,
            EKUEntry.EKU_11_SBGP_CERT_AA_SERVER_AUTH.value,
            EKUEntry.EKU_12_SCVP_RESPONDER.value,
            EKUEntry.EKU_13_EAP_OVER_PPP.value,
            EKUEntry.EKU_14_EAP_OVER_LAN.value,
            EKUEntry.EKU_15_SCVP_SERVER.value,
            EKUEntry.EKU_16_SCVP_CLIENT.value,
            EKUEntry.EKU_17_ID_KP_IPSEC_IKE.value,
            EKUEntry.EKU_18_CAPWAP_AC.value,
            EKUEntry.EKU_19_CAPWAP_WTP.value,
            EKUEntry.EKU_20_SIP_DOMAIN.value,
            EKUEntry.EKU_21_SECURE_SHELL_CLIENT.value,
            EKUEntry.EKU_22_SECURE_SHELL_SERVER.value,
            EKUEntry.EKU_23_SEND_ROUTER.value,
            EKUEntry.EKU_24_SEND_PROXY.value,
            EKUEntry.EKU_25_SEND_OWNER.value,
            EKUEntry.EKU_26_SEND_PROXIED_OWNER.value,
            EKUEntry.EKU_27_CMC_CA.value,
            EKUEntry.EKU_28_CMC_RA.value,
            EKUEntry.EKU_29_CMC_ARCHIVE.value,
            ],
        }
    ]

    # -------------------------
    # Policy Sets (Rule 1 accept, else dummy reject)
    # -------------------------
    SET_EKU_CLIENT_AUTH_EMAIL_IPSEC_TIMESTAMP_EAP_SCVP_SENDROUTER_CMC_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_EKU_CLIENT_AUTH_EMAIL_IPSEC_TIMESTAMP_EAP_SCVP_SENDROUTER_CMC, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_EKU_ALL_EXCEPT_CLIENT_AUTH_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_EKU_ALL_EXCEPT_CLIENT_AUTH, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_EKU_EAP_OVER_LAN_AND_SEND_PROXY_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_EKU_EAP_OVER_LAN_AND_SEND_PROXY, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_EKU_EAP_OVER_LAN_AND_CMC_ARCHIVE_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_EKU_EAP_OVER_LAN_AND_CMC_ARCHIVE, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_EKU_ALL_OPTIONS_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_EKU_ALL_OPTIONS, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        try:
            self.configure_lan_profile(lan_profile=LanProfile.eap_tls())
            # Step 2-3: EKUs (.2,.4,.6,.8,.14,.16,.23,.29) -> cert B -> SUCCESS
            self.dot1x.set_pre_admission_rules(self.SET_EKU_CLIENT_AUTH_EMAIL_IPSEC_TIMESTAMP_EAP_SCVP_SENDROUTER_CMC_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_B.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            #Step 4: deselect .2 -> SUCCESS
            self.dot1x.set_pre_admission_rules(self.SET_EKU_ALL_EXCEPT_CLIENT_AUTH_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            #Step 5: only (.14,.24) -> SUCCESS
            self.dot1x.set_pre_admission_rules(self.SET_EKU_EAP_OVER_LAN_AND_SEND_PROXY_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()
            self.cleanup_all_test_certificates()

            # Step 6: only (.14,.29) + swap cert B->C -> SUCCESS
            self.dot1x.set_pre_admission_rules(self.SET_EKU_EAP_OVER_LAN_AND_CMC_ARCHIVE_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_C.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()
            self.cleanup_all_test_certificates()

            # #Step 7: "ALL EKU options" + swap cert C->D (no EKUs) -> Fail
            self.dot1x.set_pre_admission_rules(self.SET_EKU_ALL_OPTIONS_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_D.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.FAILED) #TODO: implement something instead of FAILED to verify the passthrough failure
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT)
            self.verify_nic_has_no_ip_in_range()
        except Exception as e:
            log.error(f"[T1316957] FAIL: {e}")
            raise

class EAPTLSPreAdmissionEKUMultipleCriterionsTest(RadiusEapTlsTestBase):
    """
    T1316957
    Steps
    -------
    1. Disable the Windows wired NIC.
    2. Configure Pre-Admission Rule 1 (priority 1) with two EKU criteria rows:
       - EKU contains clientAuth (.2)
       - EKU contains id-kp-eapOverLAN (.14)
       Apply.
    3. Enable NIC to trigger 802.1X. Verify RADIUS-Accepted / Pre-Admission rule 1 matched (EAP-TLS).
    4. Replace client certificate with another cert that still matches Rule 1. Trigger 802.1X. Verify rule 1 matched.
    5. Configure Pre-Admission Rule 2 (priority 2) with two EKU criteria rows:
       - (scvpClient (.16) OR secureShellClient (.21))
       - (OCSPSigning (.9) OR sipDomain (.20))
       Apply.
       Replace client certificate to match Rule 2. Trigger 802.1X. Verify rule 2 matched.
    """

    # -------------------------
    # Rule Settings
    # -------------------------

    RULE_EKU_CLIENT_AUTH_AND_EAP_OVER_LAN = [
        {"criterion_name": "Certificate-Extended-Key-Usage", "criterion_value": [EKUEntry.EKU_02_CLIENT_AUTH.value]},
        {"criterion_name": "Certificate-Extended-Key-Usage", "criterion_value": [EKUEntry.EKU_14_EAP_OVER_LAN.value]},
    ]

    RULE_EKU_SCVP_OR_SSHCLIENT__AND__OCSP_OR_SIPDOMAIN = [
        {
            "criterion_name": "Certificate-Extended-Key-Usage",
            "criterion_value": [EKUEntry.EKU_16_SCVP_CLIENT.value, EKUEntry.EKU_21_SECURE_SHELL_CLIENT.value],
        },
        {
            "criterion_name": "Certificate-Extended-Key-Usage",
            "criterion_value": [EKUEntry.EKU_09_OCSP_SIGNING.value, EKUEntry.EKU_20_SIP_DOMAIN.value],
        },
    ]

    # -------------------------
    # Policy Sets
    # -------------------------
    SET_RULE_1_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_EKU_CLIENT_AUTH_AND_EAP_OVER_LAN, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_RULE_1_AND_RULE_2_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_EKU_CLIENT_AUTH_AND_EAP_OVER_LAN, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_EKU_SCVP_OR_SSHCLIENT__AND__OCSP_OR_SIPDOMAIN, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        try:
            # Step 1-3: Rule 1 only - cert E has .2 and .14, matches Rule 1
            self.dot1x.set_pre_admission_rules(self.SET_RULE_1_ACCEPT_ELSE_DENY)
            self.configure_lan_profile(lan_profile=LanProfile.eap_tls())
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_E.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            # Step 4: cert G only has .2 (no .14), doesn't match Rule 1
            # Per CSV: "Verify the host did not match Rule One" - verify Rule 2 matched (REJECT)
            self.cleanup_all_test_certificates()
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_G.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.FAILED) #TODO: implement something instead of FAILED to verify the passthrough failure
            self.verify_nic_has_no_ip_in_range()
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT)

            # Step 5: add Rule 2 (accepts .16/.21 + .9/.20), cert F matches Rule 2
            self.dot1x.set_pre_admission_rules(self.SET_RULE_1_AND_RULE_2_ACCEPT_ELSE_DENY)
            self.cleanup_all_test_certificates()
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_F.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=2)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()
        except Exception as e:
            log.error(f"[T1316957] FAIL: {e}")
            raise

class EAPTLSPreAdmissionMSCAMultipleValuesTest(RadiusEapTlsTestBase):
    """
    T1316958
    Steps
    -------
    Precondition: Install client cert B (Dot1xMSCA-CLT-B).

    1. Configure pre-admission rule: MSCA includes (.2, .4, .6, .8, .14, .16, .22, .32) (priority 1).
       Apply.
    2. Trigger 802.1X (toggle NIC). Verify RADIUS-Accepted / Pre-Admission rule 1 matched (EAP-TLS).
    3. Update rule 1: remove MSCA .2 only (keep .4, .6, .8, .14, .16, .22, .32). Apply.
       Trigger 802.1X. Verify accepted / rule 1 matched.
    4. Update rule 1: only MSCA (.14, .22). Apply.
       Trigger 802.1X. Verify accepted / rule 1 matched.
    5. Update rule 1: only MSCA (.14, .32). Apply.
       Replace cert B -> cert C. Trigger 802.1X. Verify accepted / rule 1 matched.
    6. Update rule 1: MSCA includes ALL options. Apply.
       Replace cert C -> cert D. Trigger 802.1X. Verify authentication FAILED (cert D does not match).
    """

    # Rule Settings
    RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]

    RULE_MSCA_2_4_6_8_14_16_22_32 = [
        {
            "criterion_name": "Certificate-MS-Certificate-Authority",
            "criterion_value": [
                MSCAEntry.OID_21_02_SZOID_CERTSRV_PREVIOUS_CERT_HASH.value,  # .2
                MSCAEntry.OID_21_04_SZOID_CRL_NEXT_PUBLISH.value,            # .4
                MSCAEntry.OID_21_06_SZOID_KP_KEY_RECOVERY_AGENT.value,       # .6
                MSCAEntry.OID_21_08_SZOID_ENTERPRISE_OID_ROOT.value,         # .8
                MSCAEntry.OID_21_14_SZOID_CRL_SELF_CDP.value,                # .14
                MSCAEntry.OID_21_16_SZOID_ARCHIVED_KEY_CERT_HASH.value,      # .16
                MSCAEntry.OID_21_22_SZOID_CERTSRV_CROSSCA_VERSION.value,     # .22
                MSCAEntry.OID_21_32_USER_CREDENTIALS_LOW_ASSURANCE.value,   # .32
            ],
        }
    ]

    RULE_MSCA_4_6_8_14_16_22_32 = [
        {
            "criterion_name": "Certificate-MS-Certificate-Authority",
            "criterion_value": [
                MSCAEntry.OID_21_04_SZOID_CRL_NEXT_PUBLISH.value,            # .4
                MSCAEntry.OID_21_06_SZOID_KP_KEY_RECOVERY_AGENT.value,       # .6
                MSCAEntry.OID_21_08_SZOID_ENTERPRISE_OID_ROOT.value,         # .8
                MSCAEntry.OID_21_14_SZOID_CRL_SELF_CDP.value,                # .14
                MSCAEntry.OID_21_16_SZOID_ARCHIVED_KEY_CERT_HASH.value,      # .16
                MSCAEntry.OID_21_22_SZOID_CERTSRV_CROSSCA_VERSION.value,     # .22
                MSCAEntry.OID_21_32_USER_CREDENTIALS_LOW_ASSURANCE.value,   # .32
            ],
        }
    ]

    RULE_MSCA_ONLY_14_22 = [
        {
            "criterion_name": "Certificate-MS-Certificate-Authority",
            "criterion_value": [
                MSCAEntry.OID_21_14_SZOID_CRL_SELF_CDP.value,            # .14
                MSCAEntry.OID_21_22_SZOID_CERTSRV_CROSSCA_VERSION.value, # .22
            ],
        }
    ]

    RULE_MSCA_ONLY_14_32 = [
        {
            "criterion_name": "Certificate-MS-Certificate-Authority",
            "criterion_value": [
                MSCAEntry.OID_21_14_SZOID_CRL_SELF_CDP.value,              # .14
                MSCAEntry.OID_21_32_USER_CREDENTIALS_LOW_ASSURANCE.value, # .32
            ],
        }
    ]

    # ALL MSCA options for Step 6 (using all available MSCAEntry values)
    RULE_MSCA_ALL = [
        {
            "criterion_name": "Certificate-MS-Certificate-Authority",
            "criterion_value": [
                MSCAEntry.OID_21_01_MS_CERT_SERVICES_CA_VERSION.value,       # .1
                MSCAEntry.OID_21_02_SZOID_CERTSRV_PREVIOUS_CERT_HASH.value,  # .2
                MSCAEntry.OID_21_03_SZOID_CRL_VIRTUAL_BASE.value,            # .3
                MSCAEntry.OID_21_04_SZOID_CRL_NEXT_PUBLISH.value,            # .4
                MSCAEntry.OID_21_05_SZOID_KP_CA_EXCHANGE.value,              # .5
                MSCAEntry.OID_21_06_SZOID_KP_KEY_RECOVERY_AGENT.value,       # .6
                MSCAEntry.OID_21_07_SZOID_CERTIFICATE_TEMPLATE.value,        # .7
                MSCAEntry.OID_21_08_SZOID_ENTERPRISE_OID_ROOT.value,         # .8
                MSCAEntry.OID_21_09_SZOID_RDN_DUMMY_SIGNER.value,            # .9
                MSCAEntry.OID_21_10_SZOID_APPLICATION_CERT_POLICIES.value,   # .10
                MSCAEntry.OID_21_11_SZOID_APPLICATION_POLICY_MAPPINGS.value, # .11
                MSCAEntry.OID_21_12_SZOID_APPLICATION_POLICY_CONSTRAINTS.value, # .12
                MSCAEntry.OID_21_13_SZOID_ARCHIVED_KEY_ATTR.value,           # .13
                MSCAEntry.OID_21_14_SZOID_CRL_SELF_CDP.value,                # .14
                MSCAEntry.OID_21_15_SZOID_REQUIRE_CERT_CHAIN_POLICY.value,   # .15
                MSCAEntry.OID_21_16_SZOID_ARCHIVED_KEY_CERT_HASH.value,      # .16
                MSCAEntry.OID_21_17_SZOID_ISSUED_CERT_HASH.value,            # .17
                MSCAEntry.OID_21_19_SZOID_DS_EMAIL_REPLICATION.value,        # .19
                MSCAEntry.OID_21_20_SZOID_REQUEST_CLIENT_INFO.value,         # .20
                MSCAEntry.OID_21_21_SZOID_ENCRYPTED_KEY_HASH.value,          # .21
                MSCAEntry.OID_21_22_SZOID_CERTSRV_CROSSCA_VERSION.value,     # .22
                MSCAEntry.OID_21_30_ENDORSEMENT_KEY_HIGH_ASSURANCE.value,    # .30
                MSCAEntry.OID_21_31_ENDORSEMENT_CERT_MEDIUM_ASSURANCE.value, # .31
                MSCAEntry.OID_21_32_USER_CREDENTIALS_LOW_ASSURANCE.value,    # .32
            ],
        }
    ]

    SET_MSCA_2_4_6_8_14_16_22_32_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MSCA_2_4_6_8_14_16_22_32, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_MSCA_4_6_8_14_16_22_32_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MSCA_4_6_8_14_16_22_32, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_MSCA_ONLY_14_22_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MSCA_ONLY_14_22, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_MSCA_ONLY_14_32_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MSCA_ONLY_14_32, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_MSCA_ALL_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MSCA_ALL, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        try:
            self.configure_lan_profile(lan_profile=LanProfile.eap_tls())

            # Precondition: cert B
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_MSCA_B.value
            self.import_certificates(certificate_password=CERT_PASSWORD)

            # Step 1/2: MSCA (.2, .4, .6, .8, .14, .16, .22, .32) -> ACCEPT, Rule 1 matched
            self.dot1x.set_pre_admission_rules(self.SET_MSCA_2_4_6_8_14_16_22_32_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            # Step 3: remove .2 only (.4, .6, .8, .14, .16, .22, .32) -> still ACCEPT, Rule 1 matched
            self.dot1x.set_pre_admission_rules(self.SET_MSCA_4_6_8_14_16_22_32_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            # Step 4: only .14 and .22 -> ACCEPT, Rule 1 matched
            self.dot1x.set_pre_admission_rules(self.SET_MSCA_ONLY_14_22_ACCEPT_ELSE_DENY)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            # Step 5: .14 and .32 + cert C -> ACCEPT, Rule 1 matched
            self.dot1x.set_pre_admission_rules(self.SET_MSCA_ONLY_14_32_ACCEPT_ELSE_DENY)
            self.cleanup_all_test_certificates()
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_MSCA_C.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

            # Step 6: ALL MSCA options + cert D (no MSCA values) -> Rule 1 doesn't match
            # Per CSV: "From CounterAct update the value for the Condition by selecting All options"
            self.dot1x.set_pre_admission_rules(self.SET_MSCA_ALL_ACCEPT_ELSE_DENY)
            self.cleanup_all_test_certificates()
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_MSCA_D.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.FAILED) #TODO: implement something instead of FAILED to verify the passthrough failure
            self.verify_nic_has_no_ip_in_range()
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT)
        except Exception as e:
            log.error(f"[T1316958] FAIL: {e}")
            raise

class EAPTLSPreAdmissionMSCAMultipleCriterionsTest(RadiusEapTlsTestBase):
    """
    T1316959
    Steps
    -------
    1. Configure pre-admission rule 1 (priority 1): MSCA includes (.1 and .14). Apply.
    2. Install cert E. Trigger 802.1X. Verify RADIUS-Accepted / rule 1 matched (EAP-TLS).
    3. Install cert G. Trigger 802.1X. Verify authentication should fail and rule 1 is NOT matched.
    4. Configure pre-admission rule 2 (priority 2) with two MSCA criteria rows:
       - (.5 + .19)
       - (.11 + .19)
       Apply.
    5. Install cert F. Trigger 802.1X. Verify RADIUS-Accepted / rule 2 matched (EAP-TLS).
    """

    # Rule Settings
    RULE_MSCA_CA_EXCHANGE_AND_APP_POLICY_WITH_EMAIL_REPL = [
        {
            "criterion_name": "Certificate-MS-Certificate-Authority",
            "criterion_value": [
                MSCAEntry.OID_21_05_SZOID_KP_CA_EXCHANGE.value,       # .5
                MSCAEntry.OID_21_19_SZOID_DS_EMAIL_REPLICATION.value, # .19
            ],
        },
        {
            "criterion_name": "Certificate-MS-Certificate-Authority",
            "criterion_value": [
                MSCAEntry.OID_21_11_SZOID_APPLICATION_POLICY_MAPPINGS.value, # .11
                MSCAEntry.OID_21_19_SZOID_DS_EMAIL_REPLICATION.value,        # .19
            ],
        },
    ]


    RULE_MSCA_VERSION_AND_SELF_CDP = [
    {
        "criterion_name": "Certificate-MS-Certificate-Authority",
        "criterion_value": [MSCAEntry.OID_21_01_MS_CERT_SERVICES_CA_VERSION.value],  # .1
    },
    {
        "criterion_name": "Certificate-MS-Certificate-Authority",
        "criterion_value": [MSCAEntry.OID_21_14_SZOID_CRL_SELF_CDP.value],           # .14
    },
    ]

    # Set: Rule 1 accept, else deny
    SET_RULE_1_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MSCA_VERSION_AND_SELF_CDP, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    # Set: Rule 1 accept, Rule 2 accept, else deny
    SET_RULE_1_AND_RULE_2_ACCEPT_ELSE_DENY = [
    {"cond_rules": RULE_MSCA_VERSION_AND_SELF_CDP, "auth": PreAdmissionAuth.ACCEPT},  #1 rule
    {"cond_rules": RULE_MSCA_CA_EXCHANGE_AND_APP_POLICY_WITH_EMAIL_REPL, "auth": PreAdmissionAuth.ACCEPT}, # 2 rule
    {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY}, # 3 rule
    ]

    def do_test(self):
        try:
            self.configure_lan_profile(lan_profile=LanProfile.eap_tls())

            # Step 1: Rule 1 only
            self.dot1x.set_pre_admission_rules(self.SET_RULE_1_ACCEPT_ELSE_DENY)

            # Step 2: cert E matches rule 1
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_MSCA_E.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()
            self.cleanup_all_test_certificates()

            # Step 3: cert G does NOT match rule 1 (should be rejected)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_MSCA_G.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.FAILED) #TODO: implement something instead of FAILED to verify the passthrough failure
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT)
            self.verify_nic_has_no_ip_in_range()

            # Step 4: add Rule 2 (re-apply full policy list)
            self.dot1x.set_pre_admission_rules(self.SET_RULE_1_AND_RULE_2_ACCEPT_ELSE_DENY)
            self.cleanup_all_test_certificates()

            # Step 5: cert F matches rule 2
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_MSCA_F.value
            self.import_certificates(certificate_password=CERT_PASSWORD)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=2)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])
            self.verify_authentication_on_ca()

        except Exception as e:
            log.error(f"[T1316959] FAIL: {e}")
            raise
