from framework.decorator.prametrizor import parametrize
from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus
from lib.passthrough.lan_profile_builder import LanProfile
from lib.plugin.radius.enums import LdapPorts, PreAdmissionAuth, RadiusAuthStatus
from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase


# PEAP credential constants
PEAP_DOMAIN = "txqalab"
PEAP_USER = "dotonex"
PEAP_USER_INVALID = "joenotfound"

# Pre-admission rule definitions for PEAP
RULE_EAP_TYPE_PEAP = [{"rule_name": "EAP-Type", "fields": ["PEAP"]}]
RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]

SET_ACCEPT_PEAP_ELSE_DENY = [
    {"cond_rules": RULE_EAP_TYPE_PEAP, "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": RULE_USER_NAME_MATCH_ANY_DENY_ACCESS, "auth": PreAdmissionAuth.REJECT_DUMMY},
]


@parametrize("ldap_port", [
    ("STANDARD_LDAP_TLS",),       # T1316870
    ("STANDARD_LDAP",),           # T1316879
    ("GLOBAL_CATALOG",),          # T1316888
    ("GLOBAL_CATALOG_TLS",),      # T1316897
])
class PeapHostAuthenticationWired(RadiusPeapTestBase):
    """
    T1316870 / T1316879 / T1316888 / T1316897
    DOT | Verify Host authentication using PEAP (wired)

    Steps (from CSV C147171):
    -----
    1. Configure pre-admission rule: EAP-Type = PEAP, apply, verify rule saved with priority 1.
    2. Configure PEAP credentials with domain\\username (e.g., txqalab\\dotonex).
    3. Disconnect/reconnect NIC, verify IP from configured VLAN.
    4. Verify Authentication details:
       - 802.1x Authorization Source: Pre-Admission rule 1
       - 802.1x RADIUS Authentication State: RADIUS-Accepted
       - 802.1x Authenticated Entity: User
       - 802.1x Authentication type: PEAP
    """

    def do_test(self):
        try:
            # Step 1: Configure LDAP port and pre-admission rule
            self.configure_radius_settings(
                active_directory_port_for_ldap_queries=LdapPorts[self.test_params["ldap_port"]].value
            )
            self.dot1x.set_pre_admission_rules(SET_ACCEPT_PEAP_ELSE_DENY)

            # Step 2: Configure LAN profile and PEAP credentials with domain
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            self.setup_peap_credentials(PEAP_DOMAIN, PEAP_USER)

            # Step 3: Toggle NIC to trigger authentication
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.wait_for_nic_ip_in_range()

            # Step 4: Verify authentication properties on CounterAct
            self.verify_authentication_on_ca()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties()
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


@parametrize("ldap_port", [
    ("STANDARD_LDAP_TLS",),       # T1316870 (negative)
    ("STANDARD_LDAP",),           # T1316879 (negative)
    ("GLOBAL_CATALOG",),          # T1316888 (negative)
    ("GLOBAL_CATALOG_TLS",),      # T1316897 (negative)
])
class PeapHostAuthenticationWiredNegative(RadiusPeapTestBase):
    """
    T1316870 / T1316879 / T1316888 / T1316897 (Negative scenario)
    DOT | Verify Host authentication using PEAP (wired) - Invalid User

    Steps (from CSV C147171 - negative path):
    -----
    1. Configure pre-admission rule: EAP-Type = PEAP, apply.
    2. Configure PEAP credentials with invalid username (e.g., txqalab\\joenotfound).
    3. Disconnect/reconnect NIC.
    4. Verify Authentication details:
       - 802.1x RADIUS Authentication State: RADIUS-Rejected
       - Verify the Host has no IP address on that NIC.
    """

    def do_test(self):
        try:
            # Step 1: Configure LDAP port and pre-admission rule
            self.configure_radius_settings(
                active_directory_port_for_ldap_queries=LdapPorts[self.test_params["ldap_port"]].value
            )
            self.dot1x.set_pre_admission_rules(SET_ACCEPT_PEAP_ELSE_DENY)

            # Step 2: Configure LAN profile and PEAP credentials with INVALID user
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            self.setup_peap_credentials(PEAP_DOMAIN, PEAP_USER_INVALID)

            # Step 3: Toggle NIC to trigger authentication
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.FAILED)

            # Step 4: Verify RADIUS-Rejected on CounterAct and no IP address
            # Verify the Host has no IP address on that NIC
            self.verify_nic_has_no_ip_in_range()
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


@parametrize("ldap_port", [
    ("STANDARD_LDAP_TLS",),       # T1316874
    ("STANDARD_LDAP",),           # T1316883
    ("GLOBAL_CATALOG",),          # T1316892
    ("GLOBAL_CATALOG_TLS",),      # T1316901
])
class PeapHostAuthenticationWiredWithoutDomain(RadiusPeapTestBase):
    """
    T1316874 / T1316883 / T1316892 / T1316901
    DOT | Verify Endpoint authentication with and without Domain in the Username (PEAP)

    Steps (from CSV C201917):
    -----
    1. Configure pre-admission rule: EAP-Type = PEAP, apply, verify rule saved with priority 1.
    2. Configure PEAP credentials with username only (no domain prefix).
    3. Disconnect/reconnect NIC, verify IP from configured VLAN.
    4. Verify Authentication details:
       - 802.1x RADIUS Authentication State: RADIUS-Accepted
       - 802.1x Authorization Source: Pre-Admission rule 1
       - 802.1x Authentication type: PEAP
       - 802.1x Tunneled User Name: <Username> (without domain)
    """

    def do_test(self):
        try:
            # Step 1: Configure LDAP port and pre-admission rule
            self.configure_radius_settings(
                active_directory_port_for_ldap_queries=LdapPorts[self.test_params["ldap_port"]].value
            )
            self.dot1x.set_pre_admission_rules(SET_ACCEPT_PEAP_ELSE_DENY)

            # Step 2: Configure LAN profile and PEAP credentials WITHOUT domain
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            self.setup_peap_credentials("", PEAP_USER)  # Empty domain

            # Step 3: Toggle NIC to trigger authentication
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.wait_for_nic_ip_in_range()

            # Step 4: Verify authentication properties on CounterAct
            self.verify_authentication_on_ca()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_wired_properties()
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise
