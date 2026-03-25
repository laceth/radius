"""
General 802.1X (dot1x) Functional Tests.

These tests verify general dot1x plugin health and source configuration,
independent of any specific authentication method (MAB, EAP-TLS, PEAP, etc.).
"""
from framework.log.logger import log
from tests.radius.radius_test_base import RadiusTestBase


class TC_13097_Dot1xHealthCheckTest(RadiusTestBase):
    """
    TC-13097: DOT | Perform a Health Check

    Search for any issues that might not have been seen while executing test cases.
    Verify all appliances report OK and RADIUS services are stable.

    Steps (CSV C148464)
    -------------------
    1. From the EM run the health check command:
       fstool tech-support --health-check --oneach-all -t 24h --exclude local_patches
       Verify all appliances report OK with no issues found.
    2. From the EM CLI verify the status of all RADIUS services:
       - fstool dot1x status
       - fstool oneach fstool dot1x status
       Confirm the following are running and not restarting:
       - 802.1x plugin
       - radiusd
       - winbindd
       - redis-server
    """

    def do_test(self):
        try:
            # Step 1: Run tech-support health check on EM across all appliances
            self.run_tech_support_health_check(hours=24)

            # Step 2: Verify dot1x and all subordinate services are running and stable
            self.wait_for_dot1x_ready()
            self.assert_dot1x_stable()
            log.info(f"[{self.testCaseId}] PASS - Health check completed successfully")
        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise


class TC_13099_Dot1xSourceConfigKerberosTest(RadiusTestBase):
    """
    TC-13099: DOT | Verify Source Configuration with Kerberos enabled

    Verify that configuring RADIUS with Kerberos authentication results in all
    dot1x services running correctly.

    Steps (CSV C153086)
    -------------------
    1. Add a source and join it to the domain without setting Default or NULL.
    2. Configure RADIUS settings with Kerberos authentication enabled.
    3. Run 'fstool dot1x status' and verify all services are running:
       - 802.1x plugin
       - radiusd
       - winbindd (for each configured domain)
       - redis-server
    """

    def do_test(self):
        try:
            # Step 1: Clear Default and NULL so the source is joined without either assigned.
            # Each call writes to local.properties and restarts dot1x if the value changed.
            self.dot1x.set_null("")
            self.dot1x.set_default("")

            # Step 2-3: Wait for dot1x to be fully ready and verify all services are running
            self.wait_for_dot1x_ready()
            self.assert_dot1x_stable()

            log.info(f"[{self.testCaseId}] PASS - Source configuration with Kerberos test completed")
        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise
