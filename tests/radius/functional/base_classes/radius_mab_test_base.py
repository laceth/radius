"""
Base class for MAB (MAC Authentication Bypass) functional tests.

MAB is used for endpoints that don't have 802.1X supplicants (e.g., printers, IP phones).
The switch authenticates the endpoint based on its MAC address via RADIUS.
"""
from datetime import datetime
from typing import Union

from framework.log.logger import log
from lib.passthrough.lan_profile_builder import LanProfile
from lib.plugin.radius.enums import RadiusAuthStatus
from lib.plugin.radius.models.mab_config import MABConfig
from tests.radius.radius_test_base import RadiusTestBase


class RadiusMabTestBase(RadiusTestBase):
    """
    Base class for MAB (MAC Authentication Bypass) tests.

    MAB authentication flow:
    1. Endpoint connects to switch port
    2. Switch doesn't receive 802.1X response (no supplicant)
    3. Switch sends MAC address to RADIUS server for authentication
    4. RADIUS server checks MAR (MAC Address Repository) and pre-admission rules
    5. RADIUS server returns Accept/Reject based on rules
    """

    # Default profile for MAB - 802.1X disabled
    DEFAULT_AUTH_PROFILE = "MAB"

    def __init__(self, ca, em, radius, switch, passthrough, version="1.0.0"):
        super().__init__(ca, em, radius, switch, passthrough, version)
        self.mab_config = MABConfig()
        self.nic_mac = None  # Track NIC MAC for cleanup in teardown

    def do_setup(self):
        """Setup for MAB tests - configure switch for MAB instead of dot1x."""
        log.info("=== MAB Test Setup ===")

        # Record test start time
        self.test_start_time = datetime.now()
        log.info(f"Test start time: {self.test_start_time}")

        # Configure RADIUS plugin settings
        self.configure_radius_settings()

        # Cleanup any existing endpoint before test
        self.cleanup_endpoint_by_mac(self.passthrough.mac)

        # Get VLAN from switch port config
        vlan = self.switch.port1.get('vlan')

        # Setup switch for MAB configuration (mab instead of dot1x pae authenticator)
        log.info("Configuring switch for MAB authentication")
        self.rf.setup(
            self.switch,
            port=self.switch.port1['interface'],
            radius_server_ip=self.ca.ipaddress,
            radius_secret=self.DEFAULT_RADIUS_SECRET,
            mab=True,
            vlan=vlan,
        )

        # Configure MAB LAN profile on endpoint (802.1X disabled)
        self.configure_mab_profile()

        # Get NIC MAC for MAR operations
        self.nic_mac = self.passthrough.get_nic_mac_address(self.nicname)
        log.info(f"Test NIC MAC address: {self.nic_mac}")

    def do_teardown(self):
        """Teardown for MAB tests - includes MAC cleanup from MAR."""
        log.info("=== MAB Test Teardown ===")

        # Cleanup - ensure MAC is removed from MAR
        try:
            if self.nic_mac and self.em.mac_exists_in_mar(self.nic_mac):
                self.em.remove_mac_from_mar(self.nic_mac)
                log.info(f"Cleanup: Removed MAC {self.nic_mac} from MAR")
        except Exception as cleanup_error:
            log.warning(f"MAR cleanup failed: {cleanup_error}")

        super().do_teardown()

    def configure_mab_profile(self):
        """
        Configure the endpoint with MAB LAN profile (802.1X disabled).
        Uses the LanProfile builder to generate XML on-the-fly.
        """
        log.info("Configuring MAB LAN profile (802.1X disabled)")
        super().configure_lan_profile(lan_profile=LanProfile.mab())

    def verify_authentication_on_ca(
            self,
            switch_ip: str = None,
            ca_ip: str = None,
            auth_status: Union[RadiusAuthStatus, str] = RadiusAuthStatus.ACCESS_ACCEPT,
            host_in_mar: bool = True
    ):
        """
        Verify MAB/MAR authentication properties on CounterAct.

        For Access-Reject cases, uses the MAC address directly as the host ID
        since the endpoint won't have a valid VLAN IP.

        Args:
            switch_ip: Expected Switch IP (dot1x_NAS_addr). Defaults to self.switch.ip
            ca_ip: Expected CounterACT IP (dot1x_auth_appliance). Defaults to self.ca.ipaddress
            auth_status: Expected auth status. Default: RadiusAuthStatus.ACCESS_ACCEPT
            host_in_mar: Whether the MAC is expected to be in MAR. Default: True
        """
        # Convert enum to string value if needed
        auth_status_value = auth_status.value if isinstance(auth_status, RadiusAuthStatus) else auth_status

        # For Access-Reject: use MAC as host ID (no valid IP in VLAN range)
        # For Access-Accept: use IP from _get_host_id()
        if auth_status_value == RadiusAuthStatus.ACCESS_REJECT.value:
            normalized_mac = self.nic_mac.replace("-", "").replace(":", "").lower() if self.nic_mac else ""
            host_id = normalized_mac
            log.info(f"Using MAC '{host_id}' as host ID for Access-Reject verification")
        else:
            host_id = self._get_host_id()

        log.info(f"Verifying MAB/MAR authentication for host: {host_id}")

        # Set defaults from test configuration
        switch_ip = switch_ip or self.switch.ip
        ca_ip = ca_ip or self.ca.ipaddress


        # Normalize MAC to lowercase without separators for dot1x_user check
        normalized_mac = self.nic_mac.replace("-", "").replace(":", "").lower() if self.nic_mac else ""

        # Build MAB properties check list
        # Note: dot1x_auth_state is NOT checked for MAB, use dot1x_mab_auth_status instead
        mab_properties_check_list = [
            {"property_field": "dot1x_auth_appliance", "expected_value": ca_ip},
            {"property_field": "dot1x_NAS_addr", "expected_value": switch_ip},
            {"property_field": "dot1x_NASPortIdStr", "expected_value": self.switch.port1['interface']},
            {"property_field": "dot1x_mab_auth_status", "expected_value": auth_status_value},
            {"property_field": "dot1x_fr_eap_type", "expected_value": "MAB"},
            {"property_field": "dot1x_login_type", "expected_value": "dot1x_mac_login"},
            {"property_field": "dot1x_user", "expected_value": normalized_mac},
            {"property_field": "dot1x_host_in_mar", "expected_value": "true" if host_in_mar else "false"},
        ]

        self.ca.check_properties(host_id, mab_properties_check_list)

        log.info("MAB-specific authentication verification completed")

    def assert_mac_in_mar(self, mac: str = None):
        """
        Assert that MAC address exists in MAR.

        Args:
            mac: MAC address to check. Defaults to self.nic_mac
        """
        mac = mac or self.nic_mac
        assert self.em.mac_exists_in_mar(mac), f"MAC {mac} should exist in MAR"
        log.info(f"Verified MAC {mac} exists in MAR")

    def assert_mac_not_in_mar(self, mac: str = None):
        """
        Assert that MAC address does NOT exist in MAR.

        Args:
            mac: MAC address to check. Defaults to self.nic_mac
        """
        mac = mac or self.nic_mac
        assert not self.em.mac_exists_in_mar(mac), f"MAC {mac} should NOT exist in MAR"
        log.info(f"Verified MAC {mac} does not exist in MAR")



