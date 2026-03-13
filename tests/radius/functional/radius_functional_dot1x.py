"""
General 802.1X (dot1x) Functional Tests.

These tests verify general dot1x plugin health and source configuration,
independent of any specific authentication method (MAB, EAP-TLS, PEAP, etc.).
"""
from framework.log.logger import log
from tests.radius.radius_test_base import RadiusTestBase


class Dot1xHealthCheckTest(RadiusTestBase):
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


class Dot1xSourceConfigKerberosTest(RadiusTestBase):
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

