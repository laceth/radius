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
        expected_nas_port = self.switch.port1
        expected_sanid = "URI:E2EQADeviceId://qae2e-san-testid-12345"
        try:
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)
            self.dot1x.set_pre_admission_rules(self.SET_SAN_CONTAINS_EXPECTED_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_Client_SAN.value
            self.import_certificates(certificate_password=certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
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
        expected_nas_port = self.switch.port1

        try:
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)
            self.dot1x.set_pre_admission_rules(self.SET_BASIC_WIRED_ACCEPT_TLS_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_VALID.value
            self.import_certificates(certificate_password=self.certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
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

            # Step 4: invalid OID -> should hit dummy reject (FAIL)
            self.dot1x.set_pre_admission_rules(self.SET_OID_INVALID_MATCH_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=fail_status)

            # Step 5: anyvalue -> ACCEPT
            self.dot1x.set_pre_admission_rules(self.SET_OID_ANYVALUE_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)

            # Step 6: regex -> ACCEPT
            self.dot1x.set_pre_admission_rules(self.SET_OID_REGEX_MATCH_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
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
        expected_nas_port = self.switch.port1

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
       [TODO] --need Fix for cert FIFO windows endpoint.
    """

    # -------------------------
    # Rule Settings
    # -------------------------
    #RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]

    RULE_EKU_CLIENT_AUTH_EMAIL_IPSEC_TIMESTAMP_EAP_SCVP_SENDROUTER_CMC = [
        {
            "rule_name": "Certificate-Extended-Key-Usage",
            "fields": [
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
            "rule_name": "Certificate-Extended-Key-Usage",
            "fields": [
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
            "rule_name": "Certificate-Extended-Key-Usage",
            "fields": [
                EKUEntry.EKU_14_EAP_OVER_LAN.value,  # .14
                EKUEntry.EKU_24_SEND_PROXY.value,    # .24
            ],
        }
    ]

    RULE_EKU_EAP_OVER_LAN_AND_CMC_ARCHIVE = [
        {
            "rule_name": "Certificate-Extended-Key-Usage",
            "fields": [
                EKUEntry.EKU_14_EAP_OVER_LAN.value,  # .14
                EKUEntry.EKU_29_CMC_ARCHIVE.value,   # .29
            ],
        }
    ]
    # Negative Test Cert B , EKU list entry must match all , I left out Cert B OIDs 
    RULE_EKU_EAP_NO_OVER_LAN = [
        {
            "rule_name": "Certificate-Extended-Key-Usage",
            "fields": [
                EKUEntry.EKU_03_CODE_SIGNING.value,   # .3
            ],
        }
    ]
    
    RULE_EKU_ALL_OPTIONS = [
        {
            "rule_name": "Certificate-Extended-Key-Usage",
            "fields": [
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

    SET_EKU_EAP_NO_OVER_LAN_DENY = [
        {"cond_rules": RULE_EKU_EAP_NO_OVER_LAN, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        auth_nic_profile = AuthNicProfile.EAP_TLS
        expected_status = AuthenticationStatus.SUCCEEDED
        fail_status = AuthenticationStatus.FAILED
        certificate_password = CERT_PASSWORD
        case_id = "T1316954"

        try:
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)
            # Step 2-3: EKUs (.2,.4,.6,.8,.14,.16,.23,.29) -> cert B -> SUCCESS
            self.dot1x.set_pre_admission_rules(self.SET_EKU_CLIENT_AUTH_EMAIL_IPSEC_TIMESTAMP_EAP_SCVP_SENDROUTER_CMC_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_B.value
            self.import_certificates(certificate_password=certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=1)

            #Step 4: deselect .2 ->
            self.dot1x.set_pre_admission_rules(self.SET_EKU_EAP_NO_OVER_LAN_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=fail_status)
            #self.verify_pre_admission_rule(rule_priority=2)

            #Step 5: only (.14,.24) -> SUCCESS
            self.dot1x.set_pre_admission_rules(self.SET_EKU_EAP_OVER_LAN_AND_SEND_PROXY_ACCEPT_ELSE_DENY)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=1)
            # Step 6: only (.14,.29) + swap cert B->C -> SUCCESS
            self.dot1x.set_pre_admission_rules(self.SET_EKU_EAP_OVER_LAN_AND_CMC_ARCHIVE_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_C.value
            self.import_certificates(certificate_password=certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=1)
            # #Step 7: "ALL EKU options" + swap cert C->D (no EKUs) ->
            self.dot1x.set_pre_admission_rules(self.SET_EKU_ALL_OPTIONS_ACCEPT_ELSE_DENY)
            self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_D.value
            self.import_certificates(certificate_password=certificate_password)
            self.toggle_nic()
            self.assert_authentication_status(expected_status=expected_status)
            #self.verify_pre_admission_rule(rule_priority=2) 
            log.info("[OK] CA shows Access-Reject + EAP-TLS")
        except Exception as e:
            raise