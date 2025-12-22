from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile
from tests.radius.functional.base_classes.radius_eap_tls_test_base import RadiusEapTlsTestBase


class T275181_HostAuthenticationEapTlsWired(RadiusEapTlsTestBase):
    """
    DOT | Verify Host authentication using EAP-TLS (wired)

    TestRail: https://testrail/index.php?/tests/view/275181

    Imports certificates to Windows certificate stores,
    configures LAN profile, triggers NIC toggle, and validates
    successful authentication against the RADIUS server.
    """

    def do_test(self):
        """Execute the EAP-TLS authentication test"""
        auth_nic_profile = AuthNicProfile.EAP_TLS
        certificate_password = 'aristo'
        expected_status = AuthenticationStatus.SUCCEEDED

        try:
            # Step 1: Import certificates
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


