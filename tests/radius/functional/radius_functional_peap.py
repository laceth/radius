from framework.decorator.prametrizor import parametrize
from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus
from lib.passthrough.lan_profile_builder import LanProfile
from lib.plugin.radius.enums import LdapPorts, PreAdmissionAuth, RadiusAuthStatus, RadiusFragmentSize
from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase


# PEAP credential constants
PEAP_DOMAIN = "txqalab"
PEAP_DOMAIN_2 = "txqalab2"
PEAP_USER_DOTONEX = "dotonex"
PEAP_USER_INVALID = "joenotfound"
PEAP_USER_RHUGHES = "rhughes"
PEAP_USER_E2EUSER = "e2euser"
PEAP_USER_STARTWITH_N = "NLevi"
PEAP_USER_STARTWITH_R = "Rthangaraj"
PEAP_USER_STARTWITH_T = "THampton"
PEAP_USER_ADM_SUFFIX = "-adm"
PEAP_USER_TESTUSER1 = "testuser1"
PEAP_USER_TESTUSER111 = "testuser111"
PEAP_UPN_USER_ROBH = "robh"
PEAP_UPN_DOMAIN = "txqalab.forescout.local"

# Pre-admission rule Condition: EAP-Type => PEAP
COND_EAP_TYPE_PEAP = [{"criterion_name": "EAP-Type", "criterion_value": ["PEAP"]}]
# Pre-admission rule Conditions: LDAP group => Domain*, Domain Users, or Domain Admins
COND_LDAP_GROUP_DOMAIN = [{"criterion_name": "LDAP-Group", "criterion_value": ["Domain*"]}]
COND_LDAP_GROUP_DOMAIN_USERS = [{"criterion_name": "LDAP-Group", "criterion_value": ["Domain Users"]}]
COND_LDAP_GROUP_DOMAIN_ADMINS = [{"criterion_name": "LDAP-Group", "criterion_value": ["Domain Admins"]}]
# Pre-admission rule Condition default: User-Name => .*
COND_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]

# Pre-admission rules
RULES_ACCEPT_PEAP_ELSE_DENY = [
    {"cond_rules": COND_EAP_TYPE_PEAP, "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": COND_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]
RULES_ACCEPT_LDAP_GROUP_ELSE_DENY = [
    {"cond_rules": COND_LDAP_GROUP_DOMAIN, "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": COND_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]
RULES_ACCEPT_LDAP_GROUP_DOMAIN_USERS_ELSE_DENY = [
    {"cond_rules": COND_LDAP_GROUP_DOMAIN_USERS, "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": COND_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]
RULES_ACCEPT_LDAP_GROUP_DOMAIN_ADMINS_ELSE_DENY = [
    {"cond_rules": COND_LDAP_GROUP_DOMAIN_ADMINS, "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": COND_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]
RULES_ACCEPT_LDAP_GROUP_OR_PEAP = [
    {"cond_rules": COND_LDAP_GROUP_DOMAIN, "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": COND_EAP_TYPE_PEAP, "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": COND_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]


@parametrize("ldap_port", [
    "STANDARD_LDAP_TLS",       # TS-2405
    "STANDARD_LDAP",           # TS-2406
    "GLOBAL_CATALOG",          # TS-2407
    "GLOBAL_CATALOG_TLS",      # TS-2408
])
class TC_9338_PEAPUPNAndLogonNameDiffer(RadiusPeapTestBase):
    """
    TS-2405 / TS-2406 / TS-2407 / TS-2408
    TC-9338: DOT | UPN and logon name differ (DOT-4142)

    Steps:
    -----
    1. Configure pre-admission rules: 1. EAP-Type = PEAP, 2. LDAP-Group = DOMAIN*, apply.
    2. On the domain controller, set the user's UPN (logon name) to differ from
       the pre-Windows 2000 (SAM) logon name, You can use Rob Hughes account (if not removed).
    3. Enable the EM&CA property config.upn.doesntmatch.sam via fstool oneach fstool and restart dot1x.
    4. Configure PEAP credentials using SAM format (domain\\username).
       - Verify authentication succeeds.
    5. Reconfigure PEAP credentials using UPN format (username@domain).
       - Verify authentication succeeds.
    6. Verify Authentication details on CounterAct:
       - 802.1x RADIUS Authentication State: RADIUS-Accepted
       - 802.1x Authentication type: PEAP
       ...
    """

    configure_radius_settings_in_test = True

    def do_test(self):
        try:
            # Step 1: Configure LDAP port and pre-admission rule
            self.configure_radius_settings(
                active_directory_port_for_ldap_queries=LdapPorts[self.test_params["ldap_port"]].value
            )
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_LDAP_GROUP_OR_PEAP)
            # Step 2: EM and CA property config.upn.doesntmatch.sam must be true
            cmd = "fstool oneach fstool dot1x set_property config.upn.doesntmatch.sam true"
            self.em.exec_command(cmd)
            cmd = "fstool oneach fstool dot1x restart"
            self.em.exec_command(cmd)
    
            # Step 3: Configure LAN profile
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            # Step 4: Authenticate using SAM format (domain\username)
            self.setup_peap_credentials(PEAP_DOMAIN, PEAP_USER_RHUGHES)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_authentication_on_ca()
            self.verify_pre_admission_rule(rule_priority=2)
            self.verify_wired_properties()

            # Step 5: Re-authenticate using UPN format (username@domain)
            self.setup_peap_credentials(PEAP_UPN_DOMAIN, PEAP_UPN_USER_ROBH)
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_authentication_on_ca()
            self.verify_pre_admission_rule(rule_priority=2)
            self.verify_wired_properties()
        except Exception as e:
            log.error(f"Test {self.testCaseId} with LDAP port {self.test_params['ldap_port']} failed: {e}")
            raise


@parametrize("ldap_port", [
    "STANDARD_LDAP_TLS",       # TS-2405
    "STANDARD_LDAP",           # TS-2406
    "GLOBAL_CATALOG",          # TS-2407
    "GLOBAL_CATALOG_TLS",      # TS-2408
])
class TC_9340_PEAPAuthenticationUsingLdapGroup(RadiusPeapTestBase):
    """
    TS-2405 / TS-2406 / TS-2407 / TS-2408
    TC-9340: DOT | Authenticating Using LDAP Group (DOT-4431, DOT-4835)

    Steps:
    -----
    1. Configure LDAP authentication source in CA.
    2. In CA go to Options -> Radius -> Pre-Admission Authorization and add a rule
       with condition LDAP-Group = "Domain*". Move rule to priority 1.
    3. Log into the endpoint using an Active Directory user (e.g., txqalab\\xxx-adm).
    4. Connect endpoint; verify authentication succeeds and IP is assigned.
    5. Verify 802.1x Authorization Source: Pre-Admission rule 1.
    6. Disconnect, re-authenticate with a user whose name starts with N, R, or T
       (e.g., txqalab\\rthangaraj-adm). Verify same result.
    """

    configure_radius_settings_in_test = True
    rules = [
        RULES_ACCEPT_LDAP_GROUP_ELSE_DENY,
        RULES_ACCEPT_LDAP_GROUP_DOMAIN_ADMINS_ELSE_DENY,
        RULES_ACCEPT_LDAP_GROUP_DOMAIN_USERS_ELSE_DENY
    ]
    users = [
        PEAP_USER_RHUGHES,
        PEAP_USER_STARTWITH_N,
        PEAP_USER_STARTWITH_R,
        PEAP_USER_STARTWITH_T
    ]
    # rules[0]: all users, rules[1]: users[1] only, rules[2]: users[3] only
    rule_to_users = {
        0: users,        # LDAP-Group Domain*      — test all users
        1: [users[1]],   # LDAP-Group Domain Admins — test NLevi only
        2: [users[3]],   # LDAP-Group Domain Users — test THampton only
    }

    def do_test(self):
        try:
            # Step 1 & 2: Configure LDAP port and LDAP-Group pre-admission rule
            self.configure_radius_settings(
                active_directory_port_for_ldap_queries=LdapPorts[self.test_params["ldap_port"]].value
            )
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            for rule_idx, rule in enumerate(self.rules):
                self.dot1x.set_pre_admission_rules(rule)
                for user in self.rule_to_users[rule_idx]:
                    self.setup_peap_credentials(PEAP_DOMAIN, f"{user}{PEAP_USER_ADM_SUFFIX}")
                    self.wait_for_dot1x_ready()
                    self.toggle_nic()
                    self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
                    self.verify_nic_ip_in_range()
                    self.verify_authentication_on_ca()
                    self.verify_pre_admission_rule(rule_priority=1)
                    self.verify_wired_properties()
        except Exception as e:
            log.error(f"Test {self.testCaseId} with LDAP port {self.test_params['ldap_port']} failed: {e}")
            raise


@parametrize("ldap_port", [
    "STANDARD_LDAP_TLS",       # TS-2405
    "STANDARD_LDAP",           # TS-2406
    "GLOBAL_CATALOG",          # TS-2407
    "GLOBAL_CATALOG_TLS",      # TS-2408
])
class TC_9342_PEAPHostAuthenticationWired(RadiusPeapTestBase):
    """
    TS-2405 / TS-2406 / TS-2407 / TS-2408
    TC-9342: DOT | Verify Host authentication using PEAP (wired)

    Steps:
    -----
    1. Configure pre-admission rule: EAP-Type = PEAP, apply, verify rule saved with priority 1.
    2. Configure PEAP credentials with domain\\username (e.g., txqalab\\dotonex).
    3. Disconnect/reconnect NIC, verify IP from configured VLAN.
    4. Verify Authentication details:
       - 802.1x Authorization Source: Pre-Admission rule 1
       - 802.1x RADIUS Authentication State: RADIUS-Accepted
       - 802.1x Authentication type: PEAP
    5. [Negative] Re-authenticate with invalid user (e.g., txqalab\\joenotfound).
    6. Verify Authentication details:
       - 802.1x RADIUS Authentication State: RADIUS-Rejected
       - Verify the Host has no IP address on that NIC.
    """

    configure_radius_settings_in_test = True

    def do_test(self):
        try:
            # Step 1: Configure LDAP port and pre-admission rule
            self.configure_radius_settings(
                active_directory_port_for_ldap_queries=LdapPorts[self.test_params["ldap_port"]].value
            )
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_PEAP_ELSE_DENY)
            self.configure_lan_profile(lan_profile=LanProfile.peap())

            # Step 2-4: Authenticate with valid user
            self.setup_peap_credentials(PEAP_DOMAIN, PEAP_USER_DOTONEX)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.verify_nic_ip_in_range()
            self.verify_authentication_on_ca()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties()

            # Step 5-6: Authenticate with invalid user (negative)
            self.setup_peap_credentials(PEAP_DOMAIN, PEAP_USER_INVALID)
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.FAILED)
            self.verify_nic_has_no_ip_in_range()
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT)
        except Exception as e:
            log.error(f"Test {self.testCaseId} with LDAP port {self.test_params['ldap_port']} failed: {e}")
            raise


@parametrize("ldap_port", [
    "STANDARD_LDAP_TLS",       # TS-2405
    "STANDARD_LDAP",           # TS-2406
    "GLOBAL_CATALOG",          # TS-2407
    "GLOBAL_CATALOG_TLS",      # TS-2408
])
class TC_9344_PEAPHostAuthenticationWithAndWithoutDomainWired(RadiusPeapTestBase):
    """
    TS-2405 / TS-2406 / TS-2407 / TS-2408
    TC-9344: DOT | Verify Endpoint authentication with and without Domain in the Username (PEAP)

    Steps:
    -----
    1. Configure pre-admission rule: EAP-Type = PEAP, apply, verify rule saved with priority 1.
    2. Configure PEAP credentials with domain\\username (e.g., txqalab\\dotonex).
    3. Disconnect/reconnect NIC, verify IP from configured VLAN.
    4. Verify Authentication details.
    5. Configure PEAP credentials with username only (no domain prefix).
    6. Disconnect/reconnect NIC, verify IP from configured VLAN.
    7. Verify Authentication details:
       - 802.1x RADIUS Authentication State: RADIUS-Accepted
       - 802.1x Authorization Source: Pre-Admission rule 1
       - 802.1x Authentication type: PEAP
       - 802.1x Tunneled User Name: <Username> (without domain)
    """

    configure_radius_settings_in_test = True
    credentials = [
        (PEAP_DOMAIN, PEAP_USER_DOTONEX),  # with domain: txqalab\dotonex
        ("", PEAP_USER_DOTONEX),           # without domain: dotonex
    ]

    def do_test(self):
        try:
            # Step 1: Configure LDAP port and pre-admission rule
            self.configure_radius_settings(
                active_directory_port_for_ldap_queries=LdapPorts[self.test_params["ldap_port"]].value
            )
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_PEAP_ELSE_DENY)
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            self.wait_for_dot1x_ready()

            for domain, user in self.credentials:
                self.setup_peap_credentials(domain, user)
                self.toggle_nic()
                self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
                self.verify_nic_ip_in_range()
                self.verify_authentication_on_ca()
                self.verify_pre_admission_rule(rule_priority=1)
                self.verify_wired_properties()
        except Exception as e:
            log.error(f"Test {self.testCaseId} with LDAP port {self.test_params['ldap_port']} failed: {e}")
            raise


@parametrize("ldap_port", [
    "STANDARD_LDAP_TLS",       # TS-2405
    "STANDARD_LDAP",           # TS-2406
    "GLOBAL_CATALOG",          # TS-2407
    "GLOBAL_CATALOG_TLS",      # TS-2408
])
class TC_9346_PEAPMultiDomainsAuthentication(RadiusPeapTestBase):
    """
    TS-2405 / TS-2406 / TS-2407 / TS-2408
    TC-9346: DOT | Verify authenticating a Endpoint to multiple Domains

    Steps:
    -----
    1. Configure pre-admission rule: LDAP-Group = Domain*, apply, verify rule saved with priority 1.
    2. From Host-A: disable/enable NIC, verify authentication with TXQALAB domain:
       - 802.1x Authenticating Domain: TXQALAB
       - 802.1x Authentication type: PEAP
       - 802.1x Tunneled User Name: txqalab\\<username>
    3. From Host-B or same Host-A: disable/enable NIC, verify authentication with TXQALAB2 domain:
       - 802.1x Authenticating Domain: TXQALAB2
       - 802.1x Authentication type: PEAP       
       - 802.1x Tunneled User Name: txqalab2\\e2euser
    """

    configure_radius_settings_in_test = True
    credentials = [
        (PEAP_DOMAIN, f"{PEAP_USER_RHUGHES}{PEAP_USER_ADM_SUFFIX}"),    # Host-A: txqalab\rhughes-adm
        (PEAP_DOMAIN_2, PEAP_USER_E2EUSER),  # Host-A: txqalab2\e2euser
    ]

    def do_test(self):
        try:
            # Step 1: Join domain2, Configure LDAP port and LDAP-Group = Domain* pre-admission rule
            assert self.ad_config2, "2nd Domain is required for multi-domain authentication test but was not provided in UD"
            self.dot1x.add_auth_source(self.ad_config2["ad_name"], self.ad_config2["ad_ud_user"])
            self.dot1x.join_domain(self.ad_config2["ad_name"], self.ad_config2["ad_ud_user"], self.ad_config2["ad_secret"])
            self.configure_radius_settings(
                active_directory_port_for_ldap_queries=LdapPorts[self.test_params["ldap_port"]].value
            )
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_LDAP_GROUP_ELSE_DENY)
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            self.wait_for_dot1x_ready()

            # Steps 2 & 3: Authenticate Host-A (TXQALAB) then Host-A (TXQALAB2)
            for domain, user in self.credentials:
                self.setup_peap_credentials(domain, user)
                self.toggle_nic()
                self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
                self.verify_nic_ip_in_range()
                self.verify_authentication_on_ca()
                self.verify_pre_admission_rule(rule_priority=1)
                self.verify_wired_properties()
        except Exception as e:
            log.error(f"Test {self.testCaseId} with LDAP port {self.test_params['ldap_port']} failed: {e}")
            raise


@parametrize("ldap_port", [
    "STANDARD_LDAP_TLS",       # TS-2405
    "STANDARD_LDAP",           # TS-2406
    "GLOBAL_CATALOG",          # TS-2407
    "GLOBAL_CATALOG_TLS",      # TS-2408
])
class TC_9348_PEAPUPNStartsSameAsAnotherUPN(RadiusPeapTestBase):
    """
    TC-9348: DOT | Error When UPN Starts The Same As Another UPN

    When there are multiple UPNs (User Principal Name) starting with the same name,
    the LDAP search can return multiple matches and produce an "Ambiguous" error.
    This test case verifies the fix for that issue.

    Steps:
    -----
    1. Under Options->Radius and Authentication Sources, select your Active Directory
       and click "Set Null" (handled by common do_setup via set_null).
    2. Configure a Pre-Admission rule: LDAP-Group = Domain*, apply.
    3. Authenticate on the host with testuser1:
       - Verify the host connects and authenticates successfully.
       - Verify "Ambiguous" does NOT appear in radiusd.log.
    4. Authenticate on the host with testuser111:
       - Verify the host connects and authenticates successfully.
       - Verify "Ambiguous" does NOT appear in radiusd.log.
    """

    configure_radius_settings_in_test = True
    users = [PEAP_USER_TESTUSER1, PEAP_USER_TESTUSER111]

    def do_test(self):
        try:
            # Step 2: Configure LDAP port and LDAP-Group = Domain* pre-admission rule
            self.configure_radius_settings(
                active_directory_port_for_ldap_queries=LdapPorts[self.test_params["ldap_port"]].value
            )
            self.dot1x.set_pre_admission_rules(RULES_ACCEPT_LDAP_GROUP_ELSE_DENY)
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            self.wait_for_dot1x_ready()

            # Steps 3 & 4: Authenticate with each user and verify no "Ambiguous" in radiusd.log
            for username in self.users:
                ambiguous_watcher = self.radiusd_log_collector.start_log_check(
                    patterns=[r"(?i)ambiguous"],
                    timeout=60,
                )
                self.setup_peap_credentials("", username)
                self.toggle_nic()
                self.assert_nic_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
                self.verify_nic_ip_in_range()
                self.verify_authentication_on_ca()
                self.verify_pre_admission_rule(rule_priority=1)
                self.verify_wired_properties()

                ambiguous_found, matched = self.radiusd_log_collector.get_log_check_result(ambiguous_watcher)
                assert not ambiguous_found, (
                    f"'Ambiguous' was found in radiusd.log for user '{username}': {matched}. "
                    "The UPN prefix-collision bug may not be fixed."
                )
                log.info(f"Verified: no 'Ambiguous' error in radiusd.log for user '{username}'")
        except Exception as e:
            log.error(f"Test {self.testCaseId} with LDAP port {self.test_params['ldap_port']} failed: {e}")
            raise
        
# ====================================================================================
# TC-9294 — PEAP: Setting the Fragment size (Framed-MTU = Fragment size - 30)
# ====================================================================================
@parametrize(
    "fragment_size",
    [
        (RadiusFragmentSize.SIZE_1024.name,),   # T1316989 TC-9294
        (RadiusFragmentSize.SIZE_1400.name,),   # T1316991 TC-9295
        (RadiusFragmentSize.SIZE_1230.name,),   # T1316992 TC-9296
        (RadiusFragmentSize.SIZE_500.name,),    # T1316993 TC-9297
    ],
)
class TC_9294_RadiusFragmentSizeDefaultWiredPeap(RadiusPeapTestBase):
    """
    TC-9294/TC-9295/TC-9296/TC-9297
    DOT | Verify setting the Fragment size (Framed-MTU = Fragment size - 30) from Radiusd.log

    Steps (TestRail):
    -----
    1. Options -> Radius -> Radius Settings: Set Fragment size to <fragment_size>, Apply.
    2. Options -> Radius -> Pre-Admission Authorization:
       - Add rule: EAP-Type = PEAP
         - (Optional) Add rule: EAP-Type = EAP-TLS
     3. Authenticate using PEAP and verify authenticated (rule 1).
     4. Verify radiusd.log contains the expected Framed-MTU value.
    """

    RULE_EAP_TYPE_PEAP = [{"criterion_name": "EAP-Type", "criterion_value": ["PEAP"]}]
    RULE_EAP_TYPE_EAP_TLS = [{"criterion_name": "EAP-Type", "criterion_value": ["EAP-TLS"]}]
    RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]
    PEAP_DOMAIN = "txqalab"
    PEAP_USER = "dotonex"

    def do_test(self):
        try:
            fragment_size = RadiusFragmentSize[self.test_params["fragment_size"]].value
            # Step 1: Configure fragment size in RADIUS plugin
            self.configure_radius_settings(fragment_size=fragment_size,)

            # Step 2: Configure Pre-Admission rules (PEAP + EAP-TLS, else deny)
            set_rules = [
                {"cond_rules": self.RULE_EAP_TYPE_PEAP, "auth": PreAdmissionAuth.ACCEPT},         # priority 1
                {"cond_rules": self.RULE_EAP_TYPE_EAP_TLS, "auth": PreAdmissionAuth.ACCEPT},      # priority 2
                {"cond_rules": self.RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
            ]
            self.dot1x.set_pre_admission_rules(set_rules)

            # Step 3: PEAP (rule priority 1)
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            self.setup_peap_credentials(self.PEAP_DOMAIN, self.PEAP_USER)
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
