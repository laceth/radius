"""
MAB (MAC Authentication Bypass) Functional Tests.
 
These tests verify MAB authentication scenarios where endpoints authenticate
via their MAC address instead of 802.1X credentials.
"""
from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus
from lib.passthrough.lan_profile_builder import LanProfile
from lib.plugin.radius.enums import PreAdmissionAuth, RadiusAuthStatus
from tests.radius.functional.base_classes.radius_mab_test_base import RadiusMabTestBase
from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase
from tests.radius.radius_test_base import RadiusTestBase

# =========================================================================
# Shared pre-admission rule definitions used across MAB tests
# =========================================================================
RULE_MAC_FOUND_IN_MAR_TRUE = [{"criterion_name": "MAC Found in MAR", "criterion_value": ["True"]}]
RULE_AUTH_TYPE_MAB = [{"criterion_name": "Authentication-Type", "criterion_value": ["MAB"]}]
RULE_USER_NAME_MATCH_ANY = [{"criterion_name": "User-Name", "criterion_value": ["anyvalue"]}]
UNMATCHED_MAC = "00:00:00:00:00:01"
MAB_ACCEPT_ELSE_DENY_RULES = [
    {"cond_rules": RULE_AUTH_TYPE_MAB, "auth": PreAdmissionAuth.ACCEPT},
    {"cond_rules": RULE_USER_NAME_MATCH_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
]


class Dot1xPolicyActionAddWiredMacToMARTest(RadiusPeapTestBase):
    """
    T1316907 - DOT | Policy Action - Add wired MAC to MAR

    CSV intent (C49510): Create a policy that, when a wired host authenticates
    successfully with 802.1X, runs the "802.1x Update MAR" action to add/update
    the host MAC entry in the MAC Address Repository (MAR).

        Notes / TODOs for developers:
        - The CSV includes UI-based preconditions (plugin build, relevant RADIUS/dot1x settings). Treat those as
            environmental prerequisites.
        - TODO (base modules): implement a policy-action builder that encapsulates the XML/field details so this
            test does not carry policy XML, conditions, or action-name fallbacks:
                * add_dot1x_policy_action_update_mar_add_wired_mac(mac: str, policy_name: str) -> str
                    - Conditions should scope to the endpoint MAC and successful 802.1X (e.g., Access-Accept)
                    - Action should be UI "802.1x Update MAR" (add/update entry)
        - TODO (base modules): implement EM helper for MAR waiting/verification (avoid polling loops in tests):
                * em.wait_for_mac_in_mar(mac: str, timeout: int = 180, interval: int = 5) -> None

    Steps (automation mapping):
    1. Ensure endpoint is not in MAR; disable NIC; delete endpoint (best-effort).
    2. Create/import a policy matching the endpoint MAC + `dot1x_auth_state == Access-Accept`.
    3. Configure PEAP profile/credentials; (re)connect endpoint to trigger 802.1X authentication.
    4. Verify policy matches and endpoint MAC appears in MAR.
    """

    def do_test(self):
        case_id = "T1316907"
        policy_name = f"{case_id}_dot1x_update_mar_add_wired_mac"

        # Use the passthrough MAC for wired policy/MAR operations (format varies by environment)
        nic_mac = self.passthrough.mac

        try:
            # Step 0: Ensure endpoint doesn't already exist in MAR
            # NOTE: Keep MAR cleanup/check logic in base modules.
            self.em.ensure_macs_not_in_mar([nic_mac])

            # CSV step: Disable NIC and delete endpoint from All Hosts table
            self.disable_nic()
            self.cleanup_endpoint_by_mac(self.passthrough.mac)

            # Step 1: Build/import policy with action "802.1x Update MAR"
            # Condition: endpoint MAC AND 802.1x auth state is Access-Accept
            policy_name = self.add_dot1x_policy_action_update_mar_add_wired_mac(mac=nic_mac, policy_name=policy_name)

            # Step 3: Configure PEAP and trigger wired 802.1X authentication
            self.configure_lan_profile(lan_profile=LanProfile.peap())
            self.setup_peap_credentials(domain="txqalab", username="dotonex")

            self.wait_for_dot1x_ready()
            self.enable_nic()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.SUCCEEDED)
            self.wait_for_nic_ip_in_range()

            # Step 4: Verify authentication and policy match
            self.verify_authentication_on_ca()
            self.verify_policy_match(policy_name, expected_count=1)

            # Step 5: Verify MAC was added to MAR
            self.em.wait_for_mac_in_mar(nic_mac, timeout=180, interval=5)

            log.info(f"{case_id} PASS - Policy action added wired MAC to MAR")

        except Exception as e:
            log.error(f"{case_id} FAIL: {e}")
            raise

class Dot1xPolicyActionDenyAuthenticationMABTest(RadiusMabTestBase):
        """
        T1316908 - DOT | Policy Action - Deny Authentication / MAB

        CSV intent (C50040): Create a policy to deny a wired host authenticating via
        MAB, when the host MAC exists in MAR, by using the "802.1x Update MAR" action
        with the "Deny" parameter checked.

        Manual validation mentions tcpdump for Access-Reject. Automation validates
        via CA host properties (MAB Access-Reject) and MAR target access value.

        Notes / TODOs for developers:
        - This test must run with MAB enabled (switch + endpoint) and the environment
            configured per the CSV preconditions.
        - TODO (base modules): implement a policy-action builder similar to other
            `add_dot1x_policy_*` helpers (see T1316925 pattern):
                * add_dot1x_policy_action_update_mar_deny(mac: str, policy_name: str) -> str
                    - Conditions should scope to the endpoint MAC (and optionally auth state)
                    - Action should be the "802.1x Update MAR" action with "Deny" checked,
                        which results in MAR `dot1x_target_access` being set to `reject=dummy`.
        """

        def do_test(self):
                case_id = "T1316908"
                policy_name = f"{case_id}_deny_auth_mab"

                try:
                        # Step 0: Ensure endpoint MAC exists in MAR
                        assert self.nic_mac, "Expected nic_mac to be set during setup"
                        self.em.add_mac_to_mar(mac=self.nic_mac)
                        self.assert_mac_in_mar()

                        # Step 1: Baseline MAB authentication should succeed
                        self.wait_for_dot1x_ready()
                        self.toggle_nic()
                        self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
                        self.wait_for_nic_ip_in_range()
                        self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT, host_in_mar=True)

                        # Step 2: Import policy that updates MAR to Deny for this MAC (base module responsibility)
                        policy_name = self.add_dot1x_policy_action_update_mar_deny(mac=self.nic_mac, policy_name=policy_name)

                        # Step 3: Re-authenticate via MAB and verify Access-Reject
                        self.wait_for_dot1x_ready()
                        self.toggle_nic()
                        self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
                        self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT, host_in_mar=True)

                        # Step 4: Verify policy match counter shows 1 endpoint
                        self.verify_policy_match(policy_name, expected_count=1)

                        # Step 5: Verify MAR target access is deny/reject
                        mar_entry = self.em.get_mar_entry(self.nic_mac)
                        target_access = mar_entry.get("dot1x_target_access")
                        assert target_access == PreAdmissionAuth.REJECT_DUMMY, (
                                f"[{case_id}] Expected MAR dot1x_target_access='{PreAdmissionAuth.REJECT_DUMMY}', "
                                f"got '{target_access}'. raw={mar_entry}"
                        )

                        log.info(f"{case_id} PASS - MAB denied via Update-MAR policy action")

                except Exception as e:
                        log.error(f"{case_id} FAIL: {e}")
                        raise

class MABAuthUppercaseUsernameMacAddressTest(RadiusMabTestBase):
    """
    T1316966 - DOT | Verify MAB Auth using uppercase Username and Mac address

    CSV intent (C152120): When the switch/WLC sends an uppercase MAB User-Name
    (e.g. "28:80:23:B8:2B:11"), the Radius plugin should normalize/overwrite the
    value to the expected canonical format (e.g. "288023b82b11") and allow MAB
    authentication per pre-admission authorization.

    Notes / TODOs for developers:
    - Switch precondition (manual): configure MAB request format to send uppercase
      User-Name, e.g. Cisco:
        `mab request format attribute 1 groupsize 12 separator : uppercase`
    - CounterAct preconditions (manual):
      * Options -> MAR Address Repository: add endpoint MAC
      * Disable "Accept MAB Authentication for endpoints not defined in this Repository"
      * Options -> Radius -> Pre-Admission Authorization: add rule (Priority 1):
          Authentication Type == MAB -> ACCEPT
    - TODO (base modules): provide a stable way to validate radiusd normalization
      without parsing logs in tests:
        * dot1x.verify_radiusd_username_normalization(
              received_username: str,
              normalized_username: str,
              timeout: int = 60,
          ) -> None
          - Should confirm radiusd received `received_username` and overwrote it
            to `normalized_username` (based on radiusd debug lines in the CSV).

    Steps (automation mapping):
    1. Configure pre-admission rules to ACCEPT when Authentication Type == MAB.
    2. Ensure endpoint MAC exists in MAR.
    3. Trigger MAB authentication and verify Access-Accept + Pre-Admission rule 1.
    4. Verify radiusd overwrote uppercase User-Name to normalized value (TODO base).
    """

    RULE_AUTH_TYPE_MAB = [{"rule_name": "Authentication Type", "fields": ["MAB"]}]
    RULE_USER_NAME_MATCH_ANY = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]

    SET_ALLOW_IF_MAB_ELSE_DENY = [
        {"cond_rules": RULE_AUTH_TYPE_MAB, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):

        try:
            # Step 1: Configure pre-admission rules (Priority 1: Authentication Type == MAB)
            self.dot1x.set_pre_admission_rules(self.SET_ALLOW_IF_MAB_ELSE_DENY)

            # Step 2: Ensure endpoint MAC exists in MAR (required when "Accept MAB Authentication..." is disabled)
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3: Trigger MAB authentication and verify it hits pre-admission rule 1
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()

            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT, host_in_mar=True)
            self.verify_wired_properties(nas_port_id=self.switch.port1["interface"])

            # Step 4: Verify radiusd normalized the MAB User-Name (uppercase colon-separated -> lowercase no separators)
            received_username = str(self.nic_mac).upper()
            normalized_username = str(self.nic_mac).replace(":", "").replace("-", "").lower()
            self.dot1x.verify_radiusd_username_normalization(
                received_username=received_username,
                normalized_username=normalized_username,
                timeout=60,
            )

            log.info(f" T1316966 PASS - MAB auth succeeded with uppercase User-Name normalization")

        except Exception as e:
            log.error(f"T1316966 FAIL: {e}")
            raise


class MABSimplePreAdmissionConditionsTest(RadiusMabTestBase):
    """
    T1316914 - DOT | Verify simple pre-admission conditions w/ MAB

    CSV intent (C62036): Validate that simple pre-admission conditions work for
    endpoints authenticating via MAB when the endpoint MAC exists in MAR.

    The CSV references importing attached rule files via UI. In automation we
    express the same intent by setting the pre-admission rules directly via
    `set_pre_admission_rules()`.

    Steps (automation mapping):
    1. Configure pre-admission rules: if "MAC Found in MAR" then ACCEPT, else REJECT.
    2. Ensure endpoint MAC is present in MAR.
    3. Trigger MAB authentication and verify Access-Accept + auth source "Pre-Admission rule 1".
    """

    RULE_MAC_FOUND_IN_MAR_TRUE = [{"rule_name": "MAC Found in MAR", "fields": ["True"]}]
    RULE_USER_NAME_MATCH_ANY = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]

    # Priority 1: MAC Found in MAR -> ACCEPT; fallback -> REJECT
    SET_ALLOW_IF_MAC_IN_MAR_ELSE_DENY = [
        {"cond_rules": RULE_MAC_FOUND_IN_MAR_TRUE, "auth": PreAdmissionAuth.ACCEPT},
        {"cond_rules": RULE_USER_NAME_MATCH_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
    ]

    def do_test(self):
        case_id = "T1316914"

        try:
            # Step 1: Configure simple pre-admission rules
            self.dot1x.set_pre_admission_rules(self.SET_ALLOW_IF_MAC_IN_MAR_ELSE_DENY)

            # Step 2: Ensure endpoint MAC exists in MAR (after dot1x restart)
            assert self.nic_mac, "Expected nic_mac to be set during setup"
            if not self.em.mac_exists_in_mar(self.nic_mac):
                self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 3: Authenticate via MAB and verify it hits pre-admission rule 1
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT, host_in_mar=True)
            self.verify_wired_properties(nas_port_id=self.switch.port1["interface"])

            log.info(f"T1316914 PASS - Simple pre-admission conditions validated for MAB")

        except Exception as e:
            log.error(f"T1316914 FAIL: {e}")
            raise

class MABAuthenticationDueToMARCommentTest(RadiusMabTestBase):
    """
    T1316917 - DOT | MAB authentication due to MAR comment

    CSV intent: If a pre-admission rule matches on "MAR Comment" (Any value), the
    endpoint should be authorized via that rule and receive a RADIUS Reply-Message
    attribute set by the rule.

    Notes / assumptions:
    - The environment must have "Accept MAB authentication for endpoints not defined
      in the repository" enabled (CSV precondition).
    - The framework's pre-admission-rule setter only supports configuring rule
      conditions + the authorization string (auth). Reply attributes are injected
      by appending tab-delimited `Attr=Value` pairs to the auth string.

    Steps (automation mapping):
    1. Ensure endpoint MAC is NOT present in MAR.
    2. Configure pre-admission rules:
       - Priority 1: If "MAR Comment" any value -> ACCEPT + Reply-Message
       - Fallback: reject
    3. Trigger MAB authentication and verify it hits pre-admission rule 1.
    4. Verify CA host properties contain the expected reply message text.
    """

    EXPECTED_REPLY_MESSAGE = "MAB Authentication due to MAR comment"

    RULE_MAR_COMMENT_ANY = [{"rule_name": "MAR Comment", "fields": ["anyvalue"]}]
    RULE_USER_NAME_MATCH_ANY = [{"rule_name": "User-Name", "fields": ["anyvalue"]}]

    def do_test(self):
        case_id = "T1316917"

        try:
            # Step 1: Ensure MAC is NOT present in MAR
            assert self.nic_mac, "Expected nic_mac to be set during setup"
            if self.em.mac_exists_in_mar(self.nic_mac):
                self.em.remove_mac_from_mar(self.nic_mac)

            # Step 2: Configure pre-admission rule w/ Reply-Message
            rules = [
                {
                    "cond_rules": self.RULE_MAR_COMMENT_ANY,
                    "auth": f"{PreAdmissionAuth.ACCEPT}\tReply-Message={self.EXPECTED_REPLY_MESSAGE}",
                },
                {"cond_rules": self.RULE_USER_NAME_MATCH_ANY, "auth": PreAdmissionAuth.REJECT_DUMMY},
            ]
            self.dot1x.set_pre_admission_rules(rules)

            # Step 3: Trigger MAB authentication and verify rule hit
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.wait_for_nic_ip_in_range()

            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT, host_in_mar=False)
            self.verify_wired_properties(nas_port_id=self.switch.port1["interface"])

            # Step 4: Verify Reply-Message made it into CA properties
            host_id = self._get_host_id()
            hostinfo = self.ca.exec_command(f"fstool hostinfo {host_id}")
            assert self.EXPECTED_REPLY_MESSAGE in hostinfo, (
                f"[{case_id}] Expected reply message not found in hostinfo. "
                f"expected_substring='{self.EXPECTED_REPLY_MESSAGE}'"
            )

            log.info(f"T1316917 PASS - MAB authentication due to MAR comment validated")

        except Exception as e:
            log.error(f"T1316917 FAIL: {e}")
            raise

class PolicyDetectDot1xHostMacInMARTest(RadiusTestBase):
    """
    T1316919 - DOT | Verify detecting policy property 802.1X Host Mac in MAR

    CSV intent (C64141): Validate the policy property that reports if a host's
    MAC exists in the MAC Address Repository (MAR).

    Steps (automation mapping):
    1. Create 3 synthetic endpoints using Learner plugin:
       - Endpoint 1: IP only (no MAC)
       - Endpoint 2: MAC only (no IP)
       - Endpoint 3: IP + MAC
    2. Create a custom policy with scope including "Unknown IP addresses" and
       main condition "802.1X Host Mac in MAR" filtered by a hostname prefix.
    3. Verify 0 matches when MAR is empty.
    4. Add MACs for endpoints 2 and 3 to MAR.
    5. Verify endpoints 2 and 3 match (2 matches total).

        Notes / TODOs for developers:
    - Ensure environment prerequisites from the CSV are enabled:
      * Options -> Internal Network -> "Handle new host with MAC and no IPv4 address"
      * Learner plugin installed/enabled
    - Update EP* IP/MAC values if your lab requires different identities.
        - TODO (base modules): implement the CA Learner helpers used here:
            * ca.learner_learn_ip
            * ca.learner_learn_mac
            * ca.learner_learn_ip_mac
            * ca.wait_for_hosts
            * ca.learner_retrigger
        - TODO (base modules): implement an EM helper for MAR cleanup used here:
            * em.ensure_macs_not_in_mar(macs: list[str])
        - TODO (base modules): implement a RadiusTestBase policy builder similar to
            `add_dot1x_policy_radius_fr_client_x509_cert_subj_alt_name()` (see T1316925):
            * add_dot1x_policy_dot1x_host_mac_in_mar(hostname_prefix: str, policy_name: str) -> str
                - Should call em.simple_policy_condition(..., allow_unknown_ip=True)
                - Policy condition: hostname startswith <prefix> AND dot1x_host_in_mar == true
        - Policy match verification should stay in base modules (this test uses
            `verify_policy_match()` from RadiusTestBase).
    """

    HOSTNAME_PREFIX = "T1316919_"
    POLICY_NAME = "T1316919_Mac_in_MAR"

    # TODO: update to match your environment if needed
    EP1_IP = "198.51.100.19"  # Endpoint 1: IP only
    EP2_MAC = "021316911902"  # Endpoint 2: MAC only (12 hex, no separators)
    EP3_IP = "198.51.100.29"  # Endpoint 3: IP + MAC
    EP3_MAC = "021316911903"  # Endpoint 3 MAC (different from EP2)

    def do_test(self):

        try:
            # Step 0: Ensure MAR does not contain MACs for endpoints 2 and 3
            # NOTE: Keep MAR cleanup/check logic in base modules.
            self.em.ensure_macs_not_in_mar([self.EP2_MAC, self.EP3_MAC])

            # Step 1: Create learner endpoints (per CSV examples)
            self.ca.learner_learn_ip(self.EP1_IP, hostname=f"{self.HOSTNAME_PREFIX}IPonly", online=True)
            self.ca.learner_learn_mac(self.EP2_MAC, hostname=f"{self.HOSTNAME_PREFIX}MAConly", online=True)
            self.ca.learner_learn_ip_mac(
                self.EP3_IP,
                self.EP3_MAC,
                hostname=f"{self.HOSTNAME_PREFIX}IPMAC",
                online=True,
            )
            self.ca.wait_for_hosts([self.EP1_IP, self.EP2_MAC, self.EP3_IP], timeout=90, interval=5)

            # Step 2: Import policy (include Unknown IP addresses behavior)
            # NOTE: Keep policy-building details in the base module (see T1316925 pattern).
            policy_name = self.add_dot1x_policy_dot1x_host_mac_in_mar(
                hostname_prefix=self.HOSTNAME_PREFIX,
                policy_name=self.POLICY_NAME,
            )

            # Step 3: Re-trigger policy evaluation by toggling learner online state
            self.ca.learner_retrigger([self.EP1_IP, self.EP2_MAC, self.EP3_IP])
            self.verify_policy_match(policy_name, expected_count=0)

            # Step 4: Add MACs for endpoints 2 and 3 to MAR
            self.em.add_mac_to_mar(mac=self.EP2_MAC)
            self.em.add_mac_to_mar(mac=self.EP3_MAC)

            # Step 5: Re-trigger evaluation and verify 2 matches
            self.ca.learner_retrigger([self.EP1_IP, self.EP2_MAC, self.EP3_IP])
            self.verify_policy_match(policy_name, expected_count=2)

            log.info(f"T1316919 PASS - Detecting property '802.1X Host Mac in MAR' validated")

        except Exception as e:
            log.error(f"T1316919 FAIL: {e}")
            raise


class TC_9416_MABBasicAuthWiredTest(RadiusMabTestBase):
    """
    TC-9416: DOT | Mac Address Bypass Authentication: Wired

    This test ensures authentication using MAC Address Bypass for a wired Endpoint.

    Steps
    --------------------------------
    1. Endpoint preparation — Wired AutoConfig running, IEEE 802.1X authentication
       unchecked. (Handled by base-class do_setup / configure_mab_profile.)
    2. Configure pre-admission rule: Authentication-Type = MAB → Accept; else Deny.
    3. Add the MAC address of the Endpoint to the MAC Address Repository (MAR).
       Pre-condition: "Accept MAB authentication for endpoints not defined in
       repository" must be DISABLED in Options -> Radius -> MAC Address Repository.
       (This is not a RADIUS plugin setting; it must be verified manually or as
       part of the testbed baseline before the test runs.)
    4. Force the Endpoint to authenticate (toggle NIC).
       Verify the NIC received an IP from the configured VLAN.
       Verify Authentication details: Pre-Admission rule 1, RADIUS-Accepted, MAB.
    5. Edit the MAC address of the Endpoint in MAR to be invalid (remove it),
       re-authenticate, verify the NIC has no IP and authentication is rejected.
    """

    def do_test(self):
        try:
            # Step 2: Configure pre-admission rule: Authentication-Type = MAB → Accept, else Deny
            self.dot1x.set_pre_admission_rules(MAB_ACCEPT_ELSE_DENY_RULES)

            # Step 3: Add MAC to MAR.
            # Pre-condition: "Accept MAB authentication for endpoints not defined in
            # repository" must be DISABLED in the testbed (Options -> Radius ->
            # MAC Address Repository). This is not a RADIUS plugin setting and cannot
            # be set programmatically via configure_radius_settings().
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Step 4: Authenticate and verify success
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            # Step 5: Replace the real MAC in MAR with an unmatched one so the endpoint
            # fails the MAR lookup (non-empty table, wrong entry), then re-authenticate
            # and verify rejection.
            self.em.remove_mac_from_mar(self.nic_mac)
            self.assert_mac_not_in_mar()
            self.em.add_mac_to_mar(mac=UNMATCHED_MAC)
            self.assert_mac_in_mar(UNMATCHED_MAC)

            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.verify_nic_has_no_ip_in_range()
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_REJECT, host_in_mar=False)

            log.info(f"[{self.testCaseId}] PASS - MAB basic wired authentication test completed")
        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise


class TC_9424_MABMACInMARMismatchTest(RadiusMabTestBase):
    """
    TC-9424: DOT | Pre-Admission rule - MAC Found in MAR mismatch

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
            # and properly processes the devinfo callback
            assert self.nic_mac, "Expected nic_mac to be set during setup"
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
            assert self.nic_mac, "Expected nic_mac to be set during setup"
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

            log.info(f"[{self.testCaseId}] PASS - MAC Found in MAR pre-admission rule test completed")
        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise


class TC_9435_MABSimplePreAdmissionConditionsTest(RadiusMabTestBase):
    """
    TC-9435: DOT | Verify simple pre-admission conditions w/ MAB

    Steps
    ------------------------------
    1. Configure pre-admission rule: Authentication-Type = MAB (priority 1), with
       Reply-Message attribute "Authorization by MAR entry"; else deny.
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
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            # Step 5: Verify Reply-Message in RADIUS Imposed Authorization property
            self.verify_radius_imposed_auth(self.REPLY_MESSAGE)

            log.info(f"[{self.testCaseId}] PASS - Simple pre-admission conditions with MAB test completed")
        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise


class TC_9421_MABAuthUppercaseMACTest(RadiusMabTestBase):
    """
    TC-9421: DOT | Verify MAB Auth using uppercase Username and Mac address.

    Verifies that MAB authentication works when the switch sends the MAC address
    in uppercase format. The RADIUS server should normalise the username to lowercase
    before performing MAR lookup.

    Steps
    --------------------------------
    1. Add MAC address to MAR.
    2. Disable "Accept MAB authentication for endpoints not defined in repository"
       (testbed pre-condition, not configurable via RADIUS plugin settings).
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
            self.switch.set_mab_username_format(uppercase=True)

            # Step 1: Configure pre-admission rule
            self.dot1x.set_pre_admission_rules(MAB_ACCEPT_ELSE_DENY_RULES)

            # Step 2: Add MAC to MAR (the switch may send it in uppercase format)
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Steps 3-5: Authenticate and verify
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            log.info(f"[{self.testCaseId}] PASS - MAB uppercase MAC authentication test completed")
        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise
        finally:
            self.switch.set_mab_username_format(uppercase=False)


class TC_9415_MABLargeMARTableTest(RadiusMabTestBase):
    """
    TC-9415: DOT | MAB Authentication with Large Amount of Entries in MAR Table

    This test ensures that MAR authentication works while the MAR table has a
    large number of entries in it.

    Steps
    --------------------------------
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
            self.em.add_mac_to_mar(mac=self.nic_mac)
            self.assert_mac_in_mar()

            # Steps 4-5: Authenticate and verify
            self.wait_for_dot1x_ready()
            self.toggle_nic()
            self.assert_nic_authentication_status(expected_status=AuthenticationStatus.MAB)
            self.verify_nic_ip_in_range()
            self.verify_pre_admission_rule(rule_priority=1)
            self.verify_authentication_on_ca(auth_status=RadiusAuthStatus.ACCESS_ACCEPT)
            self.verify_wired_properties(nas_port_id=self.switch.port1['interface'])

            log.info(f"[{self.testCaseId}] PASS - MAB with large MAR table test completed")
        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise
        finally:
            # Step 6: Bulk-remove imported MAR entries
            self.bulk_cleanup_mar(csv_path)
