from framework.decorator.prametrizor import parametrize
from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile
from lib.plugin.radius.enums import LdapPorts, PreAdmissionAuth
from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase

PEAP_LOGIN = {
    "domain": "txqalab",
    "domain_empty": "",
    "user": "dotonex",
    "user_invalid": "joenotfound"
}

# Pre-admission rule definitions for PEAP
RULE_EAP_TYPE_PEAP = [
    {"rule_name": "EAP-Type", "fields": ["PEAP"]}
]

RULE_USER_NAME_MATCH_ANY_DENY_ACCESS = [
    {"rule_name": "User-Name", "fields": ["anyvalue"]}
]

SET_BASIC_WIRED_ACCEPT_PEAP_ELSE_DENY = [
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

    def do_test(self):
        """Execute the PEAP credentials setup test"""
        auth_nic_profile = AuthNicProfile.PEAP
        expected_status = AuthenticationStatus.SUCCEEDED
        ldap_port = LdapPorts[self.test_params["ldap_port"]].value

        try:
            # Step 1: Configure LDAP port and pre-admission rule
            self.configure_radius_settings(active_directory_port_for_ldap_queries=ldap_port)
            self.dot1x.set_pre_admission_rules(SET_BASIC_WIRED_ACCEPT_PEAP_ELSE_DENY)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Configure PEAP credentials on Windows NIC
            self.setup_peap_credentials(PEAP_LOGIN["domain"], PEAP_LOGIN["user"])

            # Step 4: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 5: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)

            # Step 6: Wait for NIC to get IP in target VLAN range
            self.wait_for_nic_ip_in_range()

            # Step 7: Verify authentication properties on CounterAct
            self.verify_authentication_on_ca()

            # Step 8: Verify pre-admission rule is applied
            self.verify_pre_admission_rule(rule_priority=1)

            # Step 9: Verify wired properties
            self.verify_wired_properties()
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


@parametrize("ldap_port", [
    ("STANDARD_LDAP_TLS",),       # T1316870
    ("STANDARD_LDAP",),           # T1316879
    ("GLOBAL_CATALOG",),          # T1316888
    ("GLOBAL_CATALOG_TLS",),      # T1316897
])
class PeapHostAuthenticationWiredNegative(RadiusPeapTestBase):

    def do_test(self):
        """Execute the PEAP credentials setup test"""
        auth_nic_profile = AuthNicProfile.PEAP
        expected_status = AuthenticationStatus.FAILED
        ldap_port = LdapPorts[self.test_params["ldap_port"]].value

        try:
            # Step 1: Configure LDAP port and pre-admission rule
            self.configure_radius_settings(active_directory_port_for_ldap_queries=ldap_port)
            self.dot1x.set_pre_admission_rules(SET_BASIC_WIRED_ACCEPT_PEAP_ELSE_DENY)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Configure PEAP credentials on Windows NIC
            self.setup_peap_credentials(PEAP_LOGIN["domain"], PEAP_LOGIN["user_invalid"])

            # Step 4: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 5: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)

            # Step 6: Wait for NIC to get IP in target VLAN range
            self.wait_for_nic_ip_in_range()

            # Step 7: Verify authentication properties on CounterAct
            self.verify_authentication_on_ca(auth_status="Access-Reject")

            # Step 8: Verify pre-admission rule is applied
            self.verify_pre_admission_rule(rule_priority=1)

            # Step 9: Verify wired properties
            self.verify_wired_properties()
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

    def do_test(self):
        """Execute the PEAP credentials setup test"""
        auth_nic_profile = AuthNicProfile.PEAP
        expected_status = AuthenticationStatus.SUCCEEDED
        ldap_port = LdapPorts[self.test_params["ldap_port"]].value

        try:
            # Step 1: Configure LDAP port and pre-admission rule
            self.configure_radius_settings(active_directory_port_for_ldap_queries=ldap_port)
            self.dot1x.set_pre_admission_rules(SET_BASIC_WIRED_ACCEPT_PEAP_ELSE_DENY)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Configure PEAP credentials on Windows NIC
            self.setup_peap_credentials(PEAP_LOGIN["domain_empty"], PEAP_LOGIN["user"])

            # Step 4: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 5: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)

            # Step 6: Wait for NIC to get IP in target VLAN range
            self.wait_for_nic_ip_in_range()

            # Step 7: Verify authentication properties on CounterAct
            self.verify_authentication_on_ca()

            # Step 8: Verify pre-admission rule is applied
            self.verify_pre_admission_rule(rule_priority=1)

            # Step 9: Verify wired properties
            self.verify_wired_properties()
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise
