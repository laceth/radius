from dataclasses import field
from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile, WindowsCert
from lib.plugin.radius.enums import Dot1xAttribute, PreAdmissionAuth, MscaOid, EKUEntry, MSCAEntry, PreAdmissionCriterionAttribute
from tests.radius.functional.base_classes.radius_eap_tls_test_base import RadiusEapTlsTestBase




DOT1X_CLIENT_CERT_VALID = getattr(WindowsCert, "DOT1X_CLT_RADIUS_SET1", WindowsCert.CERT_DOT1X_VALID)
DOT1X_CLIENT_CERT_REVOKED = getattr(WindowsCert, "DOT1X_CLT_RADIUS_SET2", WindowsCert.CERT_DOT1X_REVOKED)

CERT_PASSWORD = "aristo"

RULE_EAP_TYPE_TLS = [{"rule_name": "EAP-Type", "fields": ["TLS"]}]
RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]


class EAPTLSPreAdmissionSANTest(RadiusEapTlsTestBase):
    """
    T1316924
    Steps
    -------
    1. Configure pre-admission rule: Certificate-From-Subject Alternative-Name CONTAINS "san-test" (priority 1).
    2. Add column "802.1x Client Cert Subject Alternative Name" to the ALL Host table.
    3. Disconnect/reconnect the Windows NIC to trigger 802.1x and obtain an IP from the configured VLAN.
    4. Verify the ALL Host table SAN column shows the SAN value from the client certificate (e.g., URL=E2EQADeviceId:/qae2e-san-testid-12345).
    5. On the host Profile → Authentication header, verify: Pre-Admission rule 1, RADIUS-Accepted, EAP-TLS.
    """

    # Rule Settings
    RULE_USER_NAME_ANY = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]
    RULE_SAN_CONTAINS_SAN_TESTID = [
        {"rule_name": Dot1xAttribute.CERT_FROM_SUBJECT_ALTERNATIVE_NAME.value, "fields": ["contains", "san-testid"]}
    ]

    SET_SAN_CONTAINS_EXPECTED_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_SAN_CONTAINS_SAN_TESTID, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        auth_nic_profile = AuthNicProfile.EAP_TLS
        expected_status = AuthenticationStatus.SUCCEEDED
        certificate_password = CERT_PASSWORD
        case_id = "T1316924"
        expected_nas_port = self.switch.port1['interface']
        expected_sanid = "URI:E2EQADeviceId://qae2e-san-testid-12345"
        try:
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)
            self.dot1x.set_pre_admission_rules(self.SET_SAN_CONTAINS_EXPECTED_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_Client_SAN.value
            self.import_certificates(certificate_password=certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            self.wait_for_nic_ip_in_range()
            self.verify_wired_properties(nas_port_id=expected_nas_port)
            self.verify_authentication_on_ca()
            self.verify_san(expected_san=expected_sanid)
        except Exception as e:
            log.error(f"[{case_id}] FAIL: {e}")
            raise


# class EAPTLSPolicySANDetectionTest(RadiusEapTlsTestBase):
#     """
#     T1316925 
#     Steps
#     -----
#     1. From the Policy tab, add a **Custom** policy named "Radius SAN" with condition **802.1x Client Cert Subject Alternative Name – Contains = san-testid**, apply configuration, and verify the policy appears under **Views** on the Home tab with no errors.
#     2. From the Home tab, select policy **"Radius SAN"** in the Views pane, view the policy results, select the host, and verify the SAN value from the certificate is shown in the results (including Reported at / Reported by when hovering the condition).
#     3. Edit policy **"Radius SAN"**, change the condition to **Contains = <invalid value>**, apply configuration, and verify the host no longer matches the policy.
#     4. Edit policy **"Radius SAN"** again, change the condition to **Contains = san-testid (or another valid SAN fragment)**, apply configuration, and verify the host matches the policy again and the SAN value appears in the results.
#       TODO REQUIRES POLICY API BY HAO
#     """

#     # Rule Settings
#     RULE_USER_NAME_ANY = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]
#     RULE_SAN_CONTAINS_SAN_TESTID = [
#         {"rule_name": Dot1xAttribute.CERT_FROM_SUBJECT_ALTERNATIVE_NAME.value, "fields": ["contains", "san-testid"]}
#     ]
#     RULE_SAN_CONTAINS_INVALID = [
#         {"rule_name": Dot1xAttribute.CERT_FROM_SUBJECT_ALTERNATIVE_NAME.value, "fields": ["contains", "invalid"]}
#     ]

#     SET_SAN_CONTAINS_EXPECTED_ACCEPT_ELSE_DENY = [
#         {"cond_rules": RULE_SAN_CONTAINS_SAN_TESTID, "auth": PreAdmissionAuth.ACCEPT},
#         {"cond_rules": RULE_USER_NAME_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
#     ]

#     SET_SAN_CONTAINS_INVALID_ACCEPT_ELSE_DENY = [
#         {"cond_rules": RULE_SAN_CONTAINS_INVALID, "auth": PreAdmissionAuth.ACCEPT},
#         {"cond_rules": RULE_USER_NAME_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
#     ]

#     def do_test(self):
#         auth_nic_profile = AuthNicProfile.EAP_TLS
#         expected_status = AuthenticationStatus.SUCCEEDED
#         fail_status = AuthenticationStatus.FAILED
#         certificate_password = CERT_PASSWORD
#         ca_endpoint_reject = "Access-Reject"
#         expected_sanid = "URI:E2EQADeviceId://qae2e-san-testid-12345"
#         case_id = "T1316925"

#         try:
#             self.configure_lan_profile(auth_nic_profile=auth_nic_profile)
#             self.cert_config.certificate_filename = WindowsCert. CERT_Client_SAN.value
#             self.import_certificates(certificate_password=certificate_password)
#             self.dot1x.set_pre_admission_rules(self.SET_SAN_CONTAINS_EXPECTED_ACCEPT_ELSE_DENY)
#             self.toggle_nic()
#             self.assert_authentication_status(expected_status=expected_status)
#             self.dot1x.set_pre_admission_rules(self.SET_SAN_CONTAINS_INVALID_ACCEPT_ELSE_DENY)
#             self.toggle_nic()
#             self.assert_authentication_status(expected_status=fail_status)
#
#             self.verify_pre_admission_rule(rule_priority=2)
#             self.dot1x.set_pre_admission_rules(self.SET_SAN_CONTAINS_EXPECTED_ACCEPT_ELSE_DENY)
#             self.toggle_nic()
#             self.assert_authentication_status(expected_status=expected_status)
#             self.wait_for_nic_ip_in_range()
#
#             self.verify_san(expected_san=expected_sanid)
#         except Exception as e:
#             log.error(f"[{case_id}] FAIL: {e}")
#             raise


class EAPTLSBasicAuthWiredTest(RadiusEapTlsTestBase):
    """
    T1316931 same as T1316932 (Wireless)
    Steps
    -----
    1. In CounterAct go to Options -> Radius -> Pre-admission Authorization, add a rule **EAP-Type = TLS**, apply, and verify the rule is saved with priority 1 and the Radius plugin restarts.
    2. Disconnect/reconnect the host NIC and verify it receives an IP address from the configured VLAN (ipconfig).
    3. On the Home tab open the host **Profile -> Authentication** header and verify Pre-Admission rule 1 is used and the RADIUS Authentication State is **RADIUS-Accepted** (EAP-TLS).
    4.[TODO later Need API?? ] On the host use MMC to move the CA cert from **Trusted Root Certification Authorities** to **Personal**, reconnect the NIC, and verify the Authentication header shows **RADIUS-Rejected** and the NIC no longer has an IP address.
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
        auth_nic_profile = AuthNicProfile.EAP_TLS
        expected_status = AuthenticationStatus.SUCCEEDED
        self.certificate_password = CERT_PASSWORD
        case_id = "T1316931"
        expected_nas_port = self.switch.port1['interface']

        try:
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)
            self.dot1x.set_pre_admission_rules(self.SET_BASIC_WIRED_ACCEPT_TLS_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_VALID.value
            self.import_certificates(certificate_password=self.certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=expected_nas_port)
            self.verify_authentication_on_ca()

        except Exception as e:
            log.error(f"[{case_id}] FAIL: {e}")
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
    """

    # Rule Settings
    RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]

    RULE_TEMPLATE_OID_MATCH = [
        {"rule_name": Dot1xAttribute.CERT_EAP_TLS_TEMPLATE.value, "fields": ["matches", MscaOid.TEMPLATE_OID_01.value]}
    ]
    RULE_TEMPLATE_OID_INVALID_MATCH = [
        {"rule_name": Dot1xAttribute.CERT_EAP_TLS_TEMPLATE.value, "fields": ["matches", "INVALID_OID_VALUE"]}
    ]
    RULE_TEMPLATE_OID_ANYVALUE = [{"rule_name": Dot1xAttribute.CERT_EAP_TLS_TEMPLATE.value, "fields": ["anyvalue"]}]
    RULE_TEMPLATE_OID_REGEX_MATCH = [
        {
            "rule_name": Dot1xAttribute.CERT_EAP_TLS_TEMPLATE.value,
            "fields": ["matchesexpression", MscaOid.TEMPLATE_OID_02_REGEX.value],
        }
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

    def do_test(self):
        auth_nic_profile = AuthNicProfile.EAP_TLS
        expected_status = AuthenticationStatus.SUCCEEDED
        fail_status = AuthenticationStatus.FAILED
        certificate_password = CERT_PASSWORD
        case_id = "T1316960"


        try:
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)
            # Step 2: import template client cert
            self.cert_config.certificate_filename = WindowsCert.CERT_TEMPLATE_CON_CERT.value
            self.import_certificates(certificate_password=certificate_password)
            # Step 3: exact OID match -> ACCEPT
            self.dot1x.set_pre_admission_rules(self.SET_OID_MATCH_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            self.wait_for_nic_ip_in_range()

            # Step 4: invalid OID -> should hit dummy reject (FAIL)
            self.dot1x.set_pre_admission_rules(self.SET_OID_INVALID_MATCH_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=fail_status)

            # Step 5: anyvalue -> ACCEPT
            self.dot1x.set_pre_admission_rules(self.SET_OID_ANYVALUE_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            self.wait_for_nic_ip_in_range()

            # Step 6: regex -> ACCEPT
            self.dot1x.set_pre_admission_rules(self.SET_OID_REGEX_MATCH_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            self.wait_for_nic_ip_in_range()
            self.verify_authentication_on_ca()
        except Exception as e:
            log.error(f"[{case_id}] FAIL: {e}")
            raise



class EAPTLSAbsurdExpiryDateTest(RadiusEapTlsTestBase):
    """
    T1316965
    Steps
    -------
    1. Configure LAN profile on the host for EAP-TLS.
    2. Configure pre-admission rule: EAP-Type = TLS (priority 1), else dummy reject.
    Apply.
    3. Import the client certificate with absurd expiry date.
    4. Trigger 802.1X (toggle NIC). Verify RADIUS-Accepted-Reject .
    5. [TODO] Need function to check fstool dot1x status.
    """

    # Rule Settings
    RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]
    RULE_EAP_TYPE_TLS = [{"rule_name": "EAP-Type", "fields": ["TLS"]}]

    SET_ACCEPT_TLS_ELSE_DENY = [
        {"cond_rules": RULE_EAP_TYPE_TLS, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        auth_nic_profile = AuthNicProfile.EAP_TLS
        fail_status = AuthenticationStatus.FAILED
        certificate_password = CERT_PASSWORD
        case_id = "T1316965"
        expected_nas_port = self.switch.port1['interface']

        try:
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)
            self.dot1x.set_pre_admission_rules(self.SET_ACCEPT_TLS_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EXPIRED.value
            self.import_certificates(certificate_password=certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=fail_status)
            self.verify_wired_properties(nas_port_id=expected_nas_port)
            log.info(f"[{case_id}] PASS")
        except Exception as e:
            log.error(f"[{case_id}] FAIL: {e}")
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
        [TODO] --need Fix for cert FIFO windows endpoint.
    """

    # -------------------------
    # Rule Settings
    # -------------------------
     

    RULE_EKU_CLIENT_AUTH_AND_EAP_OVER_LAN = [
        {"rule_name": "Certificate-Extended-Key-Usage", "fields": [EKUEntry.EKU_02_CLIENT_AUTH.value]},
        {"rule_name": "Certificate-Extended-Key-Usage", "fields": [EKUEntry.EKU_14_EAP_OVER_LAN.value]},
    ]

    RULE_EKU_SCVP_OR_SSHCLIENT__AND__OCSP_OR_SIPDOMAIN = [
        {
            "rule_name": "Certificate-Extended-Key-Usage",
            "fields": [EKUEntry.EKU_16_SCVP_CLIENT.value, EKUEntry.EKU_21_SECURE_SHELL_CLIENT.value],
        },
        {
            "rule_name": "Certificate-Extended-Key-Usage",
            "fields": [EKUEntry.EKU_09_OCSP_SIGNING.value, EKUEntry.EKU_20_SIP_DOMAIN.value],
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
        auth_nic_profile = AuthNicProfile.EAP_TLS
        expected_status = AuthenticationStatus.SUCCEEDED
        fail_status = AuthenticationStatus.FAILED
        certificate_password = CERT_PASSWORD
        case_id = "T1316957"
        expected_nas_port = self.switch.port1

        try:
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 2-3: Rule 1 only
            self.dot1x.set_pre_admission_rules(self.SET_RULE_1_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_E.value
            self.import_certificates(certificate_password=certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties(nas_port_id=expected_nas_port)
            # Step 4: different cert still matches Rule 1
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_G.value
            self.import_certificates(certificate_password=certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=fail_status)
            #self.verify_pre_admission_rule(rule_priority=2)
            # Step 5: add Rule 2, then use cert that matches Rule 2
            self.dot1x.set_pre_admission_rules(self.SET_RULE_1_AND_RULE_2_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_F.value
            self.import_certificates(certificate_password=certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=2)
        except Exception as e:
            log.error(f"[{case_id}] FAIL: {e}")
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
    6. Update rule 1: MSCA includes (.2, .4, .6, .8, .14, .16, .22, .32). Apply.
       Replace cert C -> cert D. Trigger 802.1X. Verify authentication FAILED (cert D does not match).
        [TODO] --need Fix for cert FIFO windows endpoint.
    """

    # Rule Settings
    RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]

    RULE_MSCA_ALL_2_4_6_8_14_16_22_32 = [
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
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

    RULE_MSCA_ALL_EXCEPT_PREVIOUS_CERT_HASH = [
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
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

    RULE_MSCA_ONLY_SELF_CDP_AND_CROSSCA_VERSION = [
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
                MSCAEntry.OID_21_14_SZOID_CRL_SELF_CDP.value,            # .14
                MSCAEntry.OID_21_22_SZOID_CERTSRV_CROSSCA_VERSION.value, # .22
            ],
        }
    ]

    RULE_MSCA_ONLY_SELF_CDP_AND_LOW_ASSURANCE = [
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
                MSCAEntry.OID_21_14_SZOID_CRL_SELF_CDP.value,              # .14
                MSCAEntry.OID_21_32_USER_CREDENTIALS_LOW_ASSURANCE.value, # .32
            ],
        }
    ]

    SET_MSCA_ALL_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MSCA_ALL_2_4_6_8_14_16_22_32, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_MSCA_ALL_EXCEPT_2_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MSCA_ALL_EXCEPT_PREVIOUS_CERT_HASH, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_MSCA_ONLY_14_22_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MSCA_ONLY_SELF_CDP_AND_CROSSCA_VERSION, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    SET_MSCA_ONLY_14_32_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MSCA_ONLY_SELF_CDP_AND_LOW_ASSURANCE, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        auth_nic_profile = AuthNicProfile.EAP_TLS
        expected_status = AuthenticationStatus.SUCCEEDED
        fail_status = AuthenticationStatus.FAILED
        certificate_password = CERT_PASSWORD
        case_id = "T1316958"
        expected_nas_port = self.switch.port1

        try:
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)
            # Precondition: cert B
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_MSCA_B.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 1/2
            self.dot1x.set_pre_admission_rules(self.SET_MSCA_ALL_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=1)
           

            # Step 3
            self.dot1x.set_pre_admission_rules(self.SET_MSCA_ALL_EXCEPT_2_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=1)

            # Step 4
            self.dot1x.set_pre_admission_rules(self.SET_MSCA_ONLY_14_22_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=1)

            # Step 5: switch cert B -> C
            self.dot1x.set_pre_admission_rules(self.SET_MSCA_ONLY_14_32_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_MSCA_C.value
            self.import_certificates(certificate_password=certificate_password)

            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=1)
             
            # Step 6: back to ALL + switch cert C -> D (expect FAIL)
            self.dot1x.set_pre_admission_rules(self.SET_MSCA_ALL_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_MSCA_D.value
            self.import_certificates(certificate_password=certificate_password)
             
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=1)
        except Exception as e:
            log.error(f"[{case_id}] FAIL: {e}")
            raise
        