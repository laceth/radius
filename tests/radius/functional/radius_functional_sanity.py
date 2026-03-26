"""
General 802.1X (dot1x) Functional Tests.

These tests verify general dot1x plugin health and source configuration,
independent of any specific authentication method (MAB, EAP-TLS, PEAP, etc.).
"""
from framework.log.logger import log
from tests.radius.radius_test_base import RadiusTestBase


class TC_9263_Dot1xHealthCheckTest(RadiusTestBase):
    """
    TC-9263: DOT | Perform a Health Check

    Search for any issues that might not have been seen while executing test cases.
    Verify all appliances report OK and RADIUS services are stable.

    Steps
    --------------------------------
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
            self.em.run_tech_support_health_check(hours=24)

            # Step 2: Poll until all 4 dot1x processes (802.1x plugin, radiusd,
            # winbindd, redis-server) have been running for >= 180 s (3 min).
            # Waits up to 300 s before failing.
            #
            # Design note: ideally this test would run after a full test cycle
            # with no intermediate dot1x restarts, so process uptimes would
            # exceed 2 hours. The current per-test restart design prevents that,
            # so 3 minutes is the practical minimum threshold.
            self.verify_dot1x_stable(timeout=300)

            log.info(f"[{self.testCaseId}] PASS - Health check completed successfully")
        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise


class TC_9264_Dot1xSourceConfigKerberosTest(RadiusTestBase):
    """
    TC-9264: DOT | Verify Source Configuration with Kerberos enabled

    Verify that configuring RADIUS with Kerberos authentication results in all
    dot1x services running correctly.

    Steps
    --------------------------------
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
            # set_null() and set_default() each write to local.properties and restart dot1x.
            # wait_for_dot1x_ready() between the two calls ensures restart #1 completes
            # before restart #2 is triggered.
            self.dot1x.set_null("")
            self.wait_for_dot1x_ready()
            self.dot1x.set_default("")

            # Step 2-3: Poll until all 4 dot1x processes have been running for
            # >= 180 s (3 min). Waits up to 300 s before failing.
            #
            # Design note: ideally this test would run after a full test cycle
            # with no intermediate dot1x restarts, so process uptimes would
            # exceed 2 hours. The current per-test restart design prevents that,
            # so 3 minutes is the practical minimum threshold.
            self.verify_dot1x_stable(timeout=300)

            log.info(f"[{self.testCaseId}] PASS - Source configuration with Kerberos test completed")
        except Exception as e:
            log.error(f"Test {self.testCaseId} failed: {e}")
            raise
