from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase


class RadiusPEAPCredentialsSetupTest(RadiusPeapTestBase):
    """
    Test to verify PEAP credentials setup functionality on Windows endpoint.

    This test:
    1. Prepares a PEAP configuration PowerShell script
    2. Copies it to the Windows endpoint
    3. Executes the setup_peap_credentials method
    4. Verifies the execution completed successfully
    5. Checks the log output for success markers
    """

    def do_test(self):
        """Execute the PEAP credentials setup test"""
        log_content = self.setup_peap_credentials()
        self.assert_peap_setup_successful(log_content)
