from typing import Union, cast

from framework.log.logger import log
from lib.ca.ca_common_base import CounterActBase
from lib.ca.em import EnterpriseManager
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile
from lib.passthrough.passthrough_base import PassthroughBase
from lib.plugin.radius.radius import Radius
from lib.switch.cisco_ios import CiscoIOS


class RadiusTestBase:
    # Default NIC name - can be overridden in subclasses
    DEFAULT_NICNAME = "pciPassthru0"

    def __init__(self, ca, em, radius, switch, passthrough, version="1.0.0"):
        self.ca = cast(CounterActBase, ca)
        self.em = cast(EnterpriseManager, em)
        self.version = version
        self.dot1x = cast(Radius, radius)
        self.switch = cast(CiscoIOS, switch)
        self.passthrough = cast(PassthroughBase, passthrough)
        self.nicname = self.DEFAULT_NICNAME

    def do_setup(self):
        log.info("radius common setup")

    def radius_special_setup(self):
        log.info("radius special setup")

    def do_teardown(self):
        log.info("radius common teardown")

    # =========================================================================
    # LAN Profile Management
    # =========================================================================

    def configure_lan_profile(self, auth_nic_profile: AuthNicProfile, local_profile_path: str, remote_profiles_path: str):
        """
        Configure LAN profile on the Windows endpoint.

        Args:
            auth_nic_profile: NIC profile type (determines XML filename)
            local_profile_path: Local path to the profile XML file
            remote_profiles_path: Remote directory for profiles
        """
        log.info(f"Configuring LAN profile: {auth_nic_profile.name}")

        remote_profile_path = f"{remote_profiles_path}\\{auth_nic_profile.value}"
        self.passthrough.copy_file_to_remote(local_profile_path, remote_profile_path)
        self.passthrough.delete_lan_profile(self.nicname)
        self.passthrough.add_lan_profile(remote_profile_path, self.nicname)

    # =========================================================================
    # NIC Management
    # =========================================================================

    def toggle_nic(self):
        """Toggle NIC to trigger re-authentication."""
        self.passthrough.toggle_nic(self.nicname)

    def disable_nic(self):
        """Disable the NIC."""
        self.passthrough.disable_nic(self.nicname)

    def enable_nic(self):
        """Enable the NIC."""
        self.passthrough.enable_nic(self.nicname)

    # =========================================================================
    # Assertions
    # =========================================================================

    def assert_authentication_status(
        self, expected_status: Union[AuthenticationStatus, str] = AuthenticationStatus.SUCCEEDED, timeout: int = 90
    ):
        """
        Assert NIC reaches expected authentication status.

        Args:
            expected_status: Expected authentication status
            timeout: Maximum time to wait in seconds
        """
        self.passthrough.wait_for_nic_authentication(self.nicname, expected_status=expected_status, timeout=timeout)

    def verify_authentication_on_ca(self, **kwargs):
        """
        Verify authentication status on CounterAct.

        Args:
            kwargs: Additional parameters for property check
        """
        log.info("Verifying authentication status on CounterAct")
