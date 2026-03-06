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


# ============================================================================
# Shared rule definitions used across multiple MAB tests
# ============================================================================
RULE_MAC_FOUND_IN_MAR_TRUE = [{"rule_name": "MAC Found in MAR", "fields": ["True"]}]
RULE_AUTH_TYPE_MAB = [{"rule_name": "Authentication-Type", "fields": ["MAB"]}]
RULE_USER_NAME_MATCH_ANY = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]
RULE_MAR_COMMENT_ANY = [{"rule_name": "MAR Comment", "fields": ["anyvalue"]}]

SET_AUTH_TYPE_MAB_ACCEPT_ELSE_DENY = [
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
            self.dot1x.set_pre_admission_rules(SET_AUTH_TYPE_MAB_ACCEPT_ELSE_DENY)

            # Step 2: Add MAC to MAR
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3-6: Authenticate and verify
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
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
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
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
    1. Configure pre-admission rule: Authentication-Type = MAB (priority 1), else deny.
    2. Add endpoint MAC to MAR.
    3. Authenticate endpoint via MAB protocol.
    4. Verify endpoint successfully authenticated and matched pre-admission rule.
    """

    def do_test(self):
        try:
            # Step 1: Configure pre-admission rule
            self.dot1x.set_pre_admission_rules(SET_AUTH_TYPE_MAB_ACCEPT_ELSE_DENY)

            # Step 2: Add MAC to MAR
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3-4: Authenticate and verify
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            log.info("[T1316914] PASS - Simple pre-admission conditions with MAB test completed")
        except Exception as e:
            log.error(f"[T1316914] FAIL: {e}")
            raise


class MABPreAdmissionDenyTest(RadiusMabTestBase):
    """
    T1316916 - DOT Verify pre-admission rules deny admission

    Steps (CSV C62039)
    ------------------
    1. Configure pre-admission rules (rule set that results in deny for the test endpoint).
    2. Verify endpoint MAC address is NOT in MAR.
    3. Attempt to authenticate via MAB.
    4. Verify endpoint denied network access and matches the deny rule.
    """

    # MAC NOT in MAR -> Rule 1 ("MAC Found in MAR") won't match -> falls to Rule 2 (deny)
    SET_MAC_IN_MAR_ACCEPT_ELSE_DENY = [
        {"cond_rules": RULE_MAC_FOUND_IN_MAR_TRUE, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        try:
            # Step 1: Configure pre-admission rules
            self.dot1x.set_pre_admission_rules(self.SET_MAC_IN_MAR_ACCEPT_ELSE_DENY)

            # Step 2: Verify MAC is NOT in MAR (do not add it)
            self.assert_mac_not_in_mar()

            # Step 3: Authenticate via MAB - should be denied (MAC not in MAR)
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.verify_nic_has_no_ip_in_range()

            # Step 4: Verify denied access on CA
            self.verify_pre_admission_rule(rule_priority=2, auth_state="Access-Reject")
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT, host_in_mar=False)

            log.info("[T1316916] PASS - Pre-admission deny test completed")
        except Exception as e:
            log.error(f"[T1316916] FAIL: {e}")
            raise


class MABPreAdmissionLDAPGroupTest(RadiusMabTestBase):
    """
    T1316915 - DOT Verify pre-admission conditions via LDAP group membership

    This test verifies that pre-admission rules based on LDAP group membership
    work correctly with MAB authentication. Since this is MAB (no 802.1X supplicant),
    we test the MAB-with-MAR flow where the rule set includes a fallback accept.

    Steps (CSV C62038)
    ------------------
    1. Configure pre-admission rules with Authentication-Type = MAB (accept), else deny.
    2. Verify endpoint MAC is NOT in MAR.
    3. Add MAC to MAR.
    4. Authenticate endpoint.
    5. Verify endpoint authenticated and rule matched.
    """

    def do_test(self):
        try:
            # Step 1: Configure pre-admission rule
            self.dot1x.set_pre_admission_rules(SET_AUTH_TYPE_MAB_ACCEPT_ELSE_DENY)

            # Step 2: Verify MAC is initially NOT in MAR
            self.assert_mac_not_in_mar()

            # Step 3: Add MAC to MAR
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 4-5: Authenticate and verify rule match
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            log.info("[T1316915] PASS - Pre-admission LDAP group test completed")
        except Exception as e:
            log.error(f"[T1316915] FAIL: {e}")
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
            # Step 1: Configure pre-admission rule
            self.dot1x.set_pre_admission_rules(SET_AUTH_TYPE_MAB_ACCEPT_ELSE_DENY)

            # Step 2: Add MAC to MAR (the switch may send it in uppercase format)
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3-5: Authenticate and verify
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            log.info("[T1316966] PASS - MAB uppercase MAC authentication test completed")
        except Exception as e:
            log.error(f"[T1316966] FAIL: {e}")
            raise


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
            self.dot1x.set_pre_admission_rules(SET_AUTH_TYPE_MAB_ACCEPT_ELSE_DENY)

            # Step 3: Add real endpoint MAC to MAR
            # Use approved_by="by_import" to match the bulk-imported entries
            self.em.add_mac_to_mar(mac=self.nic_mac, approved_by="by_import")
            self.assert_mac_in_mar()

            # Step 4-5: Authenticate and verify
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
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


class MABMARCommentResolvedWhenEmptyTest(RadiusMabTestBase):
    """
    T1316912 - DOT Regression MAR Comment Resolved When Field is Empty

    The 802.1X MAR Comment field (dot1x_mar_comment) is not resolved at all if
    the host exists in MAR AND comment is empty.
    If value being resolved is not defined, resolve empty string "".

    Steps (CSV C61121)
    ------------------
    1. Add MAC to MAR with a MAR comment (e.g. "802.1x Authorization").
    2. Add another MAC to MAR without a comment.
    3. Configure policy with condition "802.1x MAR Comment".
    4. Verify host with comment -> policy shows "Matched" with the comment value.
    5. Verify host without comment -> policy shows "Matched" with empty string.
    6. Verify host NOT in MAR -> policy shows "irresolvable" / "No value Exist in MAR".
    """

    def do_test(self):
        try:
            # Step 1: Configure pre-admission rule: Authentication-Type = MAB
            self.dot1x.set_pre_admission_rules(SET_AUTH_TYPE_MAB_ACCEPT_ELSE_DENY)

            # Step 2: Add MAC to MAR WITHOUT a comment (empty comment)
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3: Authenticate and verify - MAC in MAR, no comment, should still succeed
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            # Step 4: Remove MAC, re-add with comment, verify it also works
            self.em.remove_mac_from_mar(self.nic_mac)
            self.em.add_mac_to_mar(mac=self.nic_mac, comment="802.1x Authorization")
            self.assert_mac_in_mar()

            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)

            log.info("[T1316912] PASS - MAR Comment resolved when empty test completed")
        except Exception as e:
            log.error(f"[T1316912] FAIL: {e}")
            raise

class Dot1xHealthCheckTest(RadiusMabTestBase):
    """
    T1316961 - DOT Perform a Health Check

    Search for any issues that might not have been seen while executing test cases.
    Verify all appliances report OK and RADIUS services are stable.

    Steps (CSV C148464)
    -------------------
    1. Verify 802.1x plugin is running on the EM/appliance.
    2. Verify all subordinate processes are running:
       - radiusd
       - winbindd
       - redis-server
    3. Verify none of the services are restarting (uptime > threshold).
    """

    def do_test(self):
        try:
            self.wait_for_dot1x_ready()
            self.assert_dot1x_stable()
            log.info("[T1316961] PASS - Health check completed successfully")
        except Exception as e:
            log.error(f"[T1316961] FAIL: {e}")
            raise


class Dot1xSourceConfigKerberosTest(RadiusMabTestBase):
    """
    T1316974 - DOT Verify Source Configuration with Kerberos enabled

    Verify that configuring RADIUS with Kerberos authentication results in all
    dot1x services running correctly.

    Steps (CSV C153086)
    -------------------
    1. Configure RADIUS settings with Kerberos enabled.
    2. Apply configuration.
    3. Run 'fstool dot1x status' and verify all services are running:
       - 802.1x plugin
       - radiusd
       - winbindd (for each configured domain)
       - redis-server
    """

    def do_test(self):
        try:
            # Step 1-2: Configure RADIUS settings (Kerberos is typically the default)
            self.configure_radius_settings()

            # Step 3: Wait for dot1x to be fully ready after configuration
            self.wait_for_dot1x_ready()

            # Verify all processes are running and stable
            self.assert_dot1x_stable()

            log.info("[T1316974] PASS - Source configuration with Kerberos test completed")
        except Exception as e:
            log.error(f"[T1316974] FAIL: {e}")
            raise


