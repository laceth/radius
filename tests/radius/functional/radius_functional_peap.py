from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile
from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase


class T275141_HostAuthenticationPeapWired(RadiusPeapTestBase):
    """
    DOT | Verify Host authentication using PEAP (wired)

    TestRail: https://testrail/index.php?/cases/view/275141

    Configures LAN profile and 802.1X PEAP credentials on Windows NIC,
    triggers NIC toggle, and validates successful authentication
    against the RADIUS server.
    """

    def do_test(self):
        """Execute the PEAP credentials setup test"""
        auth_nic_profile = AuthNicProfile.PEAP
        peap_domain = "txqalab"
        peap_user = "dotonex"
        expected_status = AuthenticationStatus.SUCCEEDED

        try:
            # Step 1: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 2: Configure PEAP credentials on Windows NIC
            self.setup_peap_credentials(domain=peap_domain, username=peap_user)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise
