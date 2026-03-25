"""
MAB (MAC Authentication Bypass) Functional Tests.

These tests verify MAB authentication scenarios where endpoints authenticate
via their MAC address instead of 802.1X credentials.
"""
from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus
from lib.plugin.radius.enums import PreAdmissionAuth, RadiusAuthStatus
from lib.utils.mac import generate_random_mac
from tests.radius.functional.base_classes.radius_mab_test_base import RadiusMabTestBase

# =========================================================================
# Shared pre-admission rule definitions used across MAB tests
# =========================================================================
RULE_MAC_FOUND_IN_MAR_TRUE = [{"criterion_name": "MAC Found in MAR", "criterion_value": ["True"]}]
RULE_AUTH_TYPE_MAB = [{"criterion_name": "Authentication-Type", "criterion_value": ["MAB"]}]
RULE_USER_NAME_MATCH_ANY = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]

MAB_ACCEPT_ELSE_DENY_RULES = [
    {"cond_rules": RULE_AUTH_TYPE_MAB, "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": RULE_USER_NAME_MATCH_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
]


class MABBasicAuthWiredTest(RadiusMabTestBase):
    """
    T1316995 - DOT Mac Address Bypass Authentication: Wired

    This test ensures authentication using MAC Address Bypass for a wired Endpoint.

    Steps (CSV C186712)
    -------------------
    1. Configure pre-admission rule: Authentication-Type = MAB (priority 1), else deny.
    2. Add the MAC address of the Endpoint to the MAC Address Repository table.
    3. Disable "Accept MAB authentication for endpoints not defined in repository".
    4. Force the Endpoint to authenticate (toggle NIC).
    5. Verify the NIC received an IP from the configured VLAN.
    6. Verify Authentication details: Pre-Admission rule 1, RADIUS-Accepted, MAB.
    7. Edit the MAC in MAR to be invalid, re-authenticate, verify rejection.
    """

    def do_test(self):
        unmatched_mac = None
        try:
            # Step 1: Configure pre-admission rule: Authentication-Type = MAB
            self.dot1x.set_pre_admission_rules(MAB_ACCEPT_ELSE_DENY_RULES)

            # Step 2: Add MAC to MAR
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3-6: Authenticate and verify
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            # Step 7: Replace endpoint MAC with an unmatched MAC in MAR, re-authenticate, verify rejection
            self.em.remove_mac_from_mar(self.nic_mac)
            unmatched_mac = generate_random_mac()
            self.em.add_mac_to_mar(mac=unmatched_mac)
            log.info(f"Replaced endpoint MAC with unmatched MAC '{unmatched_mac}' in MAR")
            self.assert_mac_not_in_mar()  # endpoint MAC should not be in MAR

            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.verify_nic_has_no_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=2, auth_state="Access-Reject")
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT, host_in_mar=False)

            log.info("[T1316995] PASS - MAB basic wired authentication test completed")
        except Exception as e:
            log.error(f"[T1316995] FAIL: {e}")
            raise
        finally:
            if unmatched_mac:
                try:
                    self.em.remove_mac_from_mar(unmatched_mac)
                except Exception as cleanup_err:
                    log.warning(f"Failed to clean up unmatched MAC '{unmatched_mac}': {cleanup_err}")


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
        try:
            # Step 1: Set rule "MAC Found in MAR" with Deny Access
            self.dot1x.set_pre_admission_rules(self.SET_MAC_IN_MAR_DENY_ACCESS)

            # Step 2: Add MAC to MAR AFTER dot1x restart so mar.pl daemon is active
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3: Attempt to authenticate - should FAIL (MAC in MAR + Deny Access rule)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.verify_nic_has_no_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1, auth_state="Access-Reject")
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

            log.info("[T1316942] PASS - MAC Found in MAR pre-admission rule test completed")
        except Exception as e:
            log.error(f"[T1316942] FAIL: {e}")
            raise


class MABSimplePreAdmissionConditionsTest(RadiusMabTestBase):
    """
    T1316914 - DOT Verify simple pre-admission conditions w/ MAB

    Steps (CSV C62036)
    ------------------
    1. Configure pre-admission rule: Authentication-Type = MAB (priority 1), with
       Reply-Message attribute "Authorization by Pre-Admission rule 1"; else deny.
    2. Add endpoint MAC to MAR.
    3. Authenticate endpoint via MAB protocol.
    4. Verify endpoint successfully authenticated and matched pre-admission rule.
    5. Verify 802.1x RADIUS Imposed Authorization contains the expected Reply-Message.
    """

    REPLY_MESSAGE = "Authorization by MAR entry"

    SET_RULES = [
        {
            "cond_rules": RULE_AUTH_TYPE_MAB,
            "auth": f"vlan:\tIsCOA:false\tReply-Message={REPLY_MESSAGE}",
        },
        {"cond_rules": RULE_USER_NAME_MATCH_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        try:
            # Step 1: Configure pre-admission rule with Reply-Message attribute
            self.dot1x.set_pre_admission_rules(self.SET_RULES)

            # Step 2: Add MAC to MAR
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3-4: Authenticate and verify pre-admission rule
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            # Step 5: Verify Reply-Message in RADIUS Imposed Authorization property
            self.verify_radius_imposed_auth(self.REPLY_MESSAGE)

            log.info("[T1316914] PASS - Simple pre-admission conditions with MAB test completed")
        except Exception as e:
            log.error(f"[T1316914] FAIL: {e}")
            raise


class MABAuthUppercaseMACTest(RadiusMabTestBase):
    """
    T1316966 - DOT Verify MAB Auth using uppercase Username and Mac address

    Verifies that MAB authentication works when the switch sends the MAC address
    in uppercase format. The RADIUS server should normalise the username to lowercase
    before performing MAR lookup.

    Steps (CSV C152120)
    -------------------
    1. Add MAC address to MAR.
    2. Disable "Accept MAB authentication for endpoints not defined in repository".
    3. Configure pre-admission rule: Authentication-Type = MAB.
    4. Toggle NIC to trigger MAB authentication.
    5. Verify:
       - 802.1x Authorization Source: Pre-Admission rule 1
       - 802.1x RADIUS Authentication State: RADIUS-Accepted
       - 802.1x Authentication type: MAB
       - 802.1x NAS IP Address: <switch IP>
    """

    def do_test(self):
        try:
            # Precondition: configure the switch to send MAB username in uppercase format
            # mab request format attribute 1 groupsize 12 separator : uppercase
            self.switch.set_mab_username_format(uppercase=True)

            # Step 1: Configure pre-admission rule
            self.dot1x.set_pre_admission_rules(MAB_ACCEPT_ELSE_DENY_RULES)

            # Step 2: Add MAC to MAR (the switch may send it in uppercase format)
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3-5: Authenticate and verify
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            log.info("[T1316966] PASS - MAB uppercase MAC authentication test completed")
        except Exception as e:
            log.error(f"[T1316966] FAIL: {e}")
            raise
        finally:
            # Restore default MAB username format (no mab request format attribute 1)
            self.switch.set_mab_username_format(uppercase=False)


class MABLargeMARTableTest(RadiusMabTestBase):
    """
    T1317005 - DOT MAB Authentication with Large Amount of Entries in MAR Table

    This test ensures that MAR authentication works while the MAR table has a
    large number of entries in it.

    Steps (CSV C203380)
    -------------------
    1. Bulk-import ~10000 random MAR entries to the EM.
    2. Add the real endpoint MAC to MAR.
    3. Configure pre-admission rule: Authentication-Type = MAB (accept), else deny.
    4. Force the Endpoint to authenticate.
    5. Verify endpoint is on the correct VLAN and authentication details are correct.
    6. Bulk-remove imported MAR entries.
    """

    MAR_BULK_COUNT = 10000

    def do_test(self):
        csv_path = None
        try:
            # Step 1: Bulk-import random MAR entries
            csv_path = self.bulk_import_mar_entries(self.MAR_BULK_COUNT, comment="large_mar_test")

            # Step 2: Configure pre-admission rule
            self.dot1x.set_pre_admission_rules(MAB_ACCEPT_ELSE_DENY_RULES)

            # Step 3: Add real endpoint MAC to MAR
            # Use approved_by="by_import" to match the bulk-imported entries
            self.em.add_mac_to_mar(mac=self.nic_mac, approved_by="by_import")
            self.assert_mac_in_mar()

            # Step 4-5: Authenticate and verify
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            log.info("[T1317005] PASS - MAB with large MAR table test completed")
        except Exception as e:
            log.error(f"[T1317005] FAIL: {e}")
            raise
        finally:
            # Step 6: Bulk-remove imported MAR entries
            self.bulk_cleanup_mar(csv_path)
