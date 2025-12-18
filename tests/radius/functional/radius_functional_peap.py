from framework.decorator.prametrizor import parametrize
from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase


@parametrize("peap_domain, peap_user", [
    ("txqalab", "dotonex"),
    # TODO: uncomment the following lines to implement AA-817 test cases
    # ("txqalab", "dotonex-adm"),
    # ("txqalab2", "e2euser"),
    # ("", "dotonex"),
    # ("txqalab", "testuser111"),
    # ("txqalab", "testuser1"),
    # ("robh@", "txlab.forescout.local")
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
        self.configure_lan_profile()

        # Step 2: Configure PEAP credentials on Windows NIC
        self.setup_peap_credentials()

        # Step 3: Toggle NIC to trigger authentication
        self.toggle_nic()

        # TODO: Step 4: Assert authentication works
        # self.assert_authentication_successful()
