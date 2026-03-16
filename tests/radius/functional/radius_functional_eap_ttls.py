from framework.decorator.prametrizor import parametrize
from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus
from lib.passthrough.lan_profile_builder import LanProfile
from lib.plugin.radius.enums import LdapPorts, PreAdmissionAuth, RadiusAuthStatus
from tests.radius.functional.base_classes.radius_eap_ttls_test_base import RadiusEapTtlsTestBase


# ---------------------------------------------------------------------------
# Domain / user constants
# ---------------------------------------------------------------------------
DOMAIN = "txqalab"
USER_RHUGHES = "rhughes"
USER_INVALID = "joenotfound"
USER_ADM_SUFFIX = "-adm"

# ---------------------------------------------------------------------------
# Pre-admission rule building blocks
# ---------------------------------------------------------------------------
COND_EAP_TYPE_EAPTTLS = [{"criterion_name": "EAP-Type", "criterion_value": ["EAP-TTLS"]}]
COND_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]

RULES_ACCEPT_EAPTTLS = [
    {"cond_rules": COND_EAP_TYPE_EAPTTLS, "auth": PreAdmissionAuth.ACCEPT},
]


# ===========================================================================
# TC-9345 — EAP-TTLS-MSCHAPv2: with and without Domain in the Username
# ===========================================================================
@parametrize("ldap_port", [
    "STANDARD_LDAP_TLS",       # TS-2405 (LDAP+TLS+Kerberos 636)
    "STANDARD_LDAP",           # TS-2406 (Kerberos standard LDAP 389)
    "GLOBAL_CATALOG",          # TS-2407 (Kerberos with Global Catalog 3268)
    "GLOBAL_CATALOG_TLS",      # TS-2408 (Kerberos with Global Catalog TLS 3269)
])
class TC_9345_EAPTTLSHostAuthenticationWithAndWithoutDomainWired(RadiusEapTtlsTestBase):
    """
    TS-2405 / TS-2406 / TS-2407 / TS-2408
    TC-9345: DOT | Verify Endpoint authentication with and without Domain in the
             Username (EAP-TTLS-EAP-MSCHAPv2)
    Steps:
    -----
    1. Configure LDAP port and pre-admission rule: EAP-Type = EAP-TTLS → Accept.
    2. Load EAP-TTLS-EAP-MSCHAPv2 NIC profile.
    3. Authenticate with domain prefix (txqalab\\rhughes-adm):
       - toggle NIC, verify SUCCEEDED, verify IP, verify CA properties.
    4. Authenticate without domain (rhughes-adm only):
       - toggle NIC, verify SUCCEEDED, verify IP, verify CA properties.
    """

    configure_radius_settings_in_test = True

    # Pairs of (domain, username) to iterate over in the positive test
    credentials = [
        (DOMAIN, f"{USER_RHUGHES}{USER_ADM_SUFFIX}"),  # with domain:    txqalab\rhughes-adm
        ("", f"{USER_RHUGHES}{USER_ADM_SUFFIX}"),      # without domain: rhughes-adm
    ]

    def do_test(self):
        try:
            # Step 1: Configure LDAP port and EAP-TTLS pre-admission rule
            self.configure_radius_settings(
                active_directory_port_for_ldap_queries=LdapPorts[self.test_params["ldap_port"]].value
            )
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_EAPTTLS)

            # Step 2: Load EAP-TTLS-MSCHAPv2 NIC profile
            self.configure_lan_profile(lan_profile=LanProfile.eap_ttls_eap_mschapv2())

            # Steps 3 & 4: Positive auth — with domain, then without domain
            for domain, user in self.credentials:
                self.setup_eap_ttls_credentials(domain, user)
                self.wait_for_dot1x_ready()                
                self.toggle_nic()
                self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
                self.verify_nic_ip_in_range()
                self.verify_authentication_on_ca(inner_method="eap_mschapv2")
                self.verify_pre_admission_rule(rule_priority=1)
                self.verify_wired_properties()

        except Exception as e:
            log.error(f"Test {self.testCaseId} with LDAP port {self.test_params['ldap_port']} failed: {e}")
            raise


# ===========================================================================
# TC-9311 — EAP-TTLS with EAP inner method (certificate and EAP-MSCHAPv2)
# ===========================================================================
class TC_9311_EAPTTLSHostAuthenticationWithEAPMethod(RadiusEapTtlsTestBase):
    """
    TC-9311: DOT | Verify Host authentication using EAP-TTLS with a EAP method (wired)

    Inner methods: EAP-CERT and EAP-MSCHAPv2.

    Steps:
    -----
    1. Configure pre-admission rule: EAP-Type = EAP-TTLS → Accept.
    2. Add a policy with 802.1x Authentication type: EAP-TTLS.
    3. Load EAP-TTLS/EAP-TLS (cert) NIC profile.
    4. Import client certificate to Windows certificate stores.
    5. Toggle NIC; verify authentication SUCCEEDED and IP is in range.
    6. Verify CA properties: EAP-TTLS, computer login, certificate name and policy.
    7. Change NIC profile to EAP-MSCHAPv2, set user credentials, toggle NIC, verify authentication CA properties and policy again.
    8. Enter invalid credentials, toggle NIC; verify authentication FAILED and CA shows ACCESS_REJECT.
    """

    configure_radius_settings_in_test = True

    # (inner_method, lan_profile_factory, credentials_domain, credentials_user)
    # credentials_domain/user=None means cert-based (no password needed)
    eap_variants = [
        ("eap_cert",     LanProfile.eap_ttls_eap_cert,         None),
        ("eap_mschapv2", LanProfile.eap_ttls_eap_mschapv2, f"{USER_RHUGHES}{USER_ADM_SUFFIX}"),
    ]

    def do_test(self):
        try:
            # Step 1: Configure pre-admission rule: EAP-Type = EAP-TTLS → Accept
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_EAPTTLS)

            # Step 2: Add a CounterAct policy matching 802.1x Authentication Type = EAP-TTLS
            policy_name = self.add_dot1x_policy_eap_type(eap_type="TTLS")

            # Steps 3-7: Iterate over cert (EAP-TLS) and EAP-MSCHAPv2
            for inner_method, profile, username in self.eap_variants:
                log.info(f"--- Testing EAP-TTLS inner method: {inner_method} ---")

                # Load NIC profile for this variant
                self.configure_lan_profile(lan_profile=profile())
                # Set credentials for password-based variants; cert uses computer auth
                if username is not None:
                    self.setup_eap_ttls_credentials(DOMAIN, username)

                self.wait_for_dot1x_ready()
                self.toggle_nic()
                self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
                self.verify_nic_ip_in_range()
                self.verify_authentication_on_ca(inner_method=inner_method)
                self.verify_pre_admission_rule(rule_priority=1)
                self.ca.check_policy_match(policy_name)
                self.verify_wired_properties()
                #To do: check policy match

            # Step 8: Negative test — invalid credentials on EAP-MSCHAPv2 profile
            log.info("--- Step 8: Testing invalid credentials (EAP-MSCHAPv2) ---")
            self.configure_lan_profile(lan_profile=LanProfile.eap_ttls_eap_mschapv2())
            self.setup_eap_ttls_credentials(DOMAIN, USER_INVALID)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.FAILED)
            self.verify_nic_has_no_ip_in_range()
            self.verify_authentication_on_ca(
                inner_method="eap_mschapv2",
                auth_status=RadiusAuthStatus.ACCESS_REJECT,
            )

        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise


# ===========================================================================
# TC-9313 — EAP-TTLS/PAP: non-EAP inner method PAP with valid and invalid credentials
# ===========================================================================
class TC_9313_EAPTTLSHostAuthenticationWithPAP(RadiusEapTtlsTestBase):
    """
    TC-9313: DOT | Verify Host authentication using EAP-TTLS with PAP (wired)

    Inner method: PAP (non-EAP, plain password inside the TTLS tunnel).

    Preconditions:
    - Authentication Source Domain must include NULL Domain.
    - Radius Settings must have PAP Authentication option enabled.

    Steps:
    -----
    1. Configure pre-admission rule: EAP-Type = EAP-TTLS → Accept.
       Enable PAP authentication in Radius settings.
       Add a policy with 802.1x Authentication type: EAP-TTLS.
    2. Load EAP-TTLS/PAP NIC profile.
    3. Set credentials without domain prefix (NULL domain), toggle NIC; verify SUCCEEDED.
    4. Verify CA properties: EAP-TTLS, user login.
    5. Set credentials with domain prefix (txqalab\\user), toggle NIC; verify SUCCEEDED.
    6. Verify CA properties: EAP-TTLS, user login.
    7. Enter invalid credentials, toggle NIC; verify authentication FAILED and CA shows ACCESS_REJECT.
    """

    configure_radius_settings_in_test = True

    # (domain, username) pairs to test: without domain first, then with domain prefix
    credentials = [
        ("",     f"{USER_RHUGHES}{USER_ADM_SUFFIX}"),   # NULL domain
        (DOMAIN, f"{USER_RHUGHES}{USER_ADM_SUFFIX}"),   # with domain prefix
    ]

    def do_test(self):
        try:
            # Step 1: Configure PAP, set pre-admission rule, Add a policy
            self.configure_radius_settings(enable_pap_authentication="true")
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_EAPTTLS)
            policy_name = self.add_dot1x_policy_eap_type(eap_type="TTLS")

            # Step 2: Load EAP-TTLS/PAP NIC profile
            self.configure_lan_profile(lan_profile=LanProfile.eap_ttls_non_eap_pap())

            # Steps 3-6: Positive auth — without domain, then with domain prefix
            for domain, username in self.credentials:
                label = f"{domain}\\{username}" if domain else username
                log.info(f"--- Testing PAP credentials: {label} ---")
                self.setup_eap_ttls_credentials(domain, username)
                self.wait_for_dot1x_ready()
                self.toggle_nic()
                self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
                self.verify_nic_ip_in_range()
                self.verify_authentication_on_ca(inner_method="pap")
                self.verify_pre_admission_rule(rule_priority=1)
                self.verify_wired_properties()
                # To do: check policy match

            # Step 7: Negative test — invalid credentials
            log.info("--- Step 7: Testing invalid credentials (PAP) ---")
            self.setup_eap_ttls_credentials(DOMAIN, USER_INVALID)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.FAILED)
            self.verify_nic_has_no_ip_in_range()
            self.verify_authentication_on_ca(
                inner_method="pap",
                auth_status=RadiusAuthStatus.ACCESS_REJECT,
            )

        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise
        finally:
            # Special teardown step: disable PAP again for other tests
            self.configure_radius_settings(enable_pap_authentication="false")


# ===========================================================================
# TC-9315 — EAP-TTLS with Non-EAP inner method: CHAP, MSCHAP and MSCHAPv2
# ===========================================================================
class TC_9315_EAPTTLSHostAuthenticationWithNonEAPMethod(RadiusEapTtlsTestBase):
    """
    TC-9315: DOT | Verify Host authentication using EAP-TTLS with a Non-EAP method (wired)

    Inner methods: non-EAP MSCHAP/MSCHAPv2 (password-based inside the TTLS tunnel).

    Steps:
    -----
    1. Configure pre-admission rule: EAP-Type = EAP-TTLS → Accept.
       Add a policy with 802.1x Authentication type: EAP-TTLS.
    2. Load EAP-TTLS/non-EAP-MSCHAP NIC profile.
    3. Set credentials with domain prefix (txqalab\\<user>), toggle NIC;
       verify authentication SUCCEEDED and IP is in range.
    4. Verify CA properties: EAP-TTLS, user login.
    5. Verify policy matched.
    6. Change NIC profile to EAP-TTLS/non-EAP-MSCHAPv2, toggle NIC, verify authentication SUCCEEDED and CA properties and policy again.
    7. Enter invalid credentials, toggle NIC; verify authentication FAILED and CA shows ACCESS_REJECT.
    """

    # (inner_method, profile_factory, domain, username)
    non_eap_variants = [       
        ("mschap",   LanProfile.eap_ttls_non_eap_mschap),    # non-EAP MSCHAP
        ("mschapv2", LanProfile.eap_ttls_non_eap_mschapv2)  # non-EAP MSCHAPv2
    ]

    def do_test(self):
        try:
            # Step 1: Configure pre-admission rule and add EAP-TTLS policy
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_EAPTTLS)
            policy_name = self.add_dot1x_policy_eap_type(eap_type="TTLS")

            # Steps 2-7: Iterate over non-EAP MSCHAP, then non-EAP MSCHAPv2
            for inner_method, profile in self.non_eap_variants:
                log.info(f"--- Testing EAP-TTLS inner method: non EAP {inner_method} ---")
                self.configure_lan_profile(lan_profile=profile())
                self.setup_eap_ttls_credentials(DOMAIN, f"{USER_RHUGHES}{USER_ADM_SUFFIX}")
                self.wait_for_dot1x_ready()
                self.toggle_nic()
                self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
                self.verify_nic_ip_in_range()
                self.verify_authentication_on_ca(inner_method=inner_method)
                self.verify_pre_admission_rule(rule_priority=1)
                self.ca.check_policy_match(policy_name)
                self.verify_wired_properties()               
                # To do: check policy match

            # Step 8: Negative test — invalid credentials on non-EAP MSCHAPv2 profile
            log.info("--- Step 8: Testing invalid credentials ---")
            self.setup_eap_ttls_credentials(DOMAIN, USER_INVALID)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.FAILED)
            self.verify_nic_has_no_ip_in_range()
            self.verify_authentication_on_ca(
                inner_method="mschapv2",
                auth_status=RadiusAuthStatus.ACCESS_REJECT,
            )

        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise
