from framework.decorator.prametrizor import parametrize
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile
from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase


@parametrize("peap_domain, peap_user, expected_status", [
    ("txqalab", "dotonex", AuthenticationStatus.SUCCEEDED),
    ("txqalab", "invalid_user", AuthenticationStatus.FAILED),
])
class RadiusPEAPCredentialsSetupTest(RadiusPeapTestBase):
    """
    Verify RADIUS PEAP authentication with different user credentials.

    Configures 802.1X PEAP credentials on Windows NIC and validates
    successful authentication against the RADIUS server.
    """

    def do_test(self):
        """Execute the PEAP credentials setup test"""
        # Step 1: Configure LAN profile
        self.configure_lan_profile(auth_nic_profile=AuthNicProfile.PEAP)

        # Step 2: Configure PEAP credentials on Windows NIC
        self.setup_peap_credentials(domain=self.peap_domain, username=self.peap_user)

        # Step 3: Toggle NIC to trigger authentication
        self.toggle_nic()

        # Step 4: Assert authentication status matches expected
        self.assert_authentication_status(expected_status=self.expected_status)
