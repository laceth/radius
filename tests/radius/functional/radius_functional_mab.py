"""
MAB (MAC Authentication Bypass) Functional Tests.

These tests verify MAB authentication scenarios where endpoints authenticate
via their MAC address instead of 802.1X credentials.
"""
from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus
from lib.plugin.radius.enums import PreAdmissionAuth, RadiusAuthStatus
from tests.radius.functional.base_classes.radius_mab_test_base import RadiusMabTestBase


class MABMACInMARMismatchTest(RadiusMabTestBase):
    """
    T1316942 - DOT Pre-Admission rule - MAC Found in MAR mismatch

    This test verifies that pre-admission rules using "MAC Found in MAR" condition
    correctly match/deny hosts based on MAR presence.

    Steps
    -----
    1. Create pre-admission rule with condition "MAC Found in MAR" set to Deny Access.
    2. Ensure MAR contains host MAC.
    3. Attempt to authenticate - should FAIL due to match with deny rule.
    4. Edit rule to Allow Access (remove Deny Access checkbox).
    5. Attempt to authenticate - should SUCCEED, auth source = Pre-Admission rule 1.
    """

    # Rule Settings
    RULE_MAC_FOUND_IN_MAR_TRUE = [{"rule_name": "MAC Found in MAR", "fields": ["True"]}]
    RULE_USER_NAME_MATCH_ANY = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]

    # "Deny Access" checked: MAC Found in MAR -> REJECT, fallback -> REJECT
    SET_MAC_IN_MAR_DENY_ACCESS = [
        {"cond_rules": RULE_MAC_FOUND_IN_MAR_TRUE, "auth": PreAdmissionAuth.REJECT_DUMMY},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    # "Allow Access": MAC Found in MAR -> ACCEPT, fallback -> REJECT
    SET_MAC_IN_MAR_ALLOW_ACCESS = [
        {"cond_rules": RULE_MAC_FOUND_IN_MAR_TRUE, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        case_id = "T1316942"

        try:
            # Step 1: Set rule "MAC Found in MAR" with Deny Access
            # This writes to local.properties and restarts dot1x
            self.dot1x.set_pre_admission_rules(self.SET_MAC_IN_MAR_DENY_ACCESS)

            # Step 2: Add MAC to MAR AFTER dot1x restart so mar.pl daemon is active
            # and properly processes the devinfo callback
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3: Attempt to authenticate - should FAIL (MAC in MAR + Deny Access rule)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.verify_nic_has_no_ip_in_range()
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT)

            # Step 4: Change rule to Allow Access (restarts dot1x again)
            self.dot1x.set_pre_admission_rules(self.SET_MAC_IN_MAR_ALLOW_ACCESS)

            # Re-add MAC after dot1x restart to ensure mar.pl picks it up
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 5: Attempt to authenticate - should SUCCEED (MAC in MAR + ACCEPT rule)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            log.info(f"[{case_id}] PASS - MAC Found in MAR pre-admission rule test completed")

        except Exception as e:
            log.error(f"[{case_id}] FAIL: {e}")
            raise


