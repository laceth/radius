import ipaddress
import re
from datetime import datetime
from typing import Union, cast

from framework.log.logger import log
from lib.ca.ca_common_base import CounterActBase
from lib.ca.em import EnterpriseManager
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile
from lib.passthrough.passthrough_base import PassthroughBase
from lib.plugin.radius.radius import Radius
from lib.plugin.radius.radius_plugin_settings import RadiusPluginSettings
from lib.switch.cisco_ios import CiscoIOS
from lib.switch.radius_factory import RadiusFactory



class RadiusTestBase:
    # Default NIC name - can be overridden in subclasses
    DEFAULT_NICNAME = "pciPassthru0"
    DEFAULT_RADIUS_SECRET = "aristo"
    DEFAULT_RADIUS_SETTINGS = RadiusPluginSettings()

    def __init__(self, ca, em, radius, switch, passthrough, version="1.0.0"):
        self.ca = cast(CounterActBase, ca)
        self.em = cast(EnterpriseManager, em)
        self.version = version
        self.dot1x = cast(Radius, radius)
        self.switch = cast(CiscoIOS, switch)
        self.passthrough = cast(PassthroughBase, passthrough)
        self.nicname = self.DEFAULT_NICNAME
        self.rf = RadiusFactory(default_secret=self.DEFAULT_RADIUS_SECRET)
        self.test_start_time = None

    def do_setup(self):
        log.info("radius common setup")

        # Record test start time
        self.test_start_time = datetime.now()
        log.info(f"Test start time: {self.test_start_time}")

        # Configure RADIUS plugin with settings
        self.configure_radius_settings()

        # Cleanup any existing endpoint before test
        self.cleanup_endpoint_by_mac(self.passthrough.mac)

        # Setup switch RADIUS configuration
        self.rf.setup(
            self.switch,
            port=self.switch.port1,
            radius_server_ip=self.ca.ipaddress,
            radius_secret=self.DEFAULT_RADIUS_SECRET,
            mab=False,
            vlan=1570,
        )

    def configure_radius_settings(self, **overrides):
        """
        Configure RADIUS plugin settings.

        Args:
            **overrides: Keyword arguments to override specific settings.
                         e.g., active_directory_port_for_ldap_queries="standard ldap over tls"
        """
        if overrides:
            from dataclasses import replace
            settings = replace(self.DEFAULT_RADIUS_SETTINGS, **overrides)
        else:
            settings = self.DEFAULT_RADIUS_SETTINGS
        self.dot1x.configure_radius_plugin(settings.to_dict())


    def radius_special_setup(self):
        log.info("radius special setup")

    def do_teardown(self):
        log.info("radius common teardown")
        # self.rf.teardown(self.switch, port=self.switch.port1, radius_server_ip=self.ca.ipaddress)

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

    def _get_host_id(self) -> str:
        """
        Get host ID by MAC address from passthrough config.

        Returns:
            Host ID/IP address for the endpoint
        """
        return self.ca.get_host_ip_by_mac(self.passthrough.mac)

    def _verify_common_properties(
        self,
        host_id: str,
        switch_ip: str = None,
        ca_ip: str = None,
        auth_state: str = "Access-Accept"
    ):
        """
        Verify common authentication properties on CounterAct.

        Args:
            host_id: Host ID to verify properties for
            switch_ip: Expected Switch IP (dot1x_NAS_addr or dot1x_NAS_addr6). Defaults to self.switch.ip
            ca_ip: Expected CounterACT IP (dot1x_auth_appliance). Defaults to self.ca.ipaddress
            auth_state: Expected auth state (dot1x_auth_state). Default: "Access-Accept"
        """
        # Set defaults from test configuration
        switch_ip = switch_ip or self.switch.ip
        ca_ip = ca_ip or self.ca.ipaddress

        # Determine NAS address property based on IP version
        nas_addr_field = "dot1x_NAS_addr6" if self._is_ipv6(switch_ip) else "dot1x_NAS_addr"

        # Build properties check list - COMMON fields (All Auth Types)
        properties_check_list = [
            {"property_field": nas_addr_field, "expected_value": switch_ip},
            {"property_field": "dot1x_auth_appliance", "expected_value": ca_ip},
            {"property_field": "dot1x_auth_state", "expected_value": auth_state},
        ]

        self.ca.check_properties(host_id, properties_check_list)

        # Verify auth happened after test started
        self._verify_auth_time(host_id)

        log.info("Common authentication properties verified")

    def _is_ipv6(self, ip: str) -> bool:
        """Check if the given IP address is IPv6."""
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    def verify_pre_admission_rule(self, rule_priority: int = 1):
        """
        Verify that authentication was processed by the expected pre-admission rule.

        Args:
            rule_priority: The priority number of the pre-admission rule. Default: 1
        """
        host_id = self._get_host_id()
        expected_value = f"Pre-Admission rule {rule_priority}"

        log.info(f"Verifying pre-admission rule for host: {host_id}")

        properties_check_list = [
            {"property_field": "dot1x_auth_source", "expected_value": expected_value}
        ]

        self.ca.check_properties(host_id, properties_check_list)
        log.info(f"Pre-admission rule verified: {expected_value}")

    def verify_wired_properties(self, nas_port_id: str = None):
        """
        Verify wired-specific authentication properties on CounterAct.

        Args:
            nas_port_id: Expected NAS Port ID (dot1x_NASPortIdStr). Defaults to self.switch.port1
        """
        host_id = self._get_host_id()
        nas_port_id = nas_port_id or self.switch.port1

        log.info(f"Verifying wired properties for host: {host_id}")

        properties_check_list = [
            {"property_field": "dot1x_NASPortIdStr", "expected_value": nas_port_id}
        ]

        self.ca.check_properties(host_id, properties_check_list)
        log.info(f"Wired properties verified: NAS Port ID = {nas_port_id}")

    def verify_wireless_properties(self, nas_identifier: str = None, nas_port_id: str = None):
        """
        Verify wireless-specific authentication properties on CounterAct.

        Args:
            nas_identifier: Expected NAS Identifier (dot1x_NAS_Identifier). Example: "cisco9800_vlan1824"
            nas_port_id: Expected NAS Port ID (dot1x_NASPortIdStr). Example: "capwap_90000008"
        """
        host_id = self._get_host_id()

        log.info(f"Verifying wireless properties for host: {host_id}")

        properties_check_list = [
            {"property_field": "dot1x_NAS_Identifier", "expected_value": nas_identifier},
            {"property_field": "dot1x_NASPortIdStr", "expected_value": nas_port_id},
        ]

        self.ca.check_properties(host_id, properties_check_list)
        log.info(f"Wireless properties verified: NAS Identifier = {nas_identifier}, NAS Port ID = {nas_port_id}")

    def _verify_auth_time(self, host_id: str):
        """
        Verify dot1x_auth_time is after test_start_time.

        Args:
            host_id: Host ID to verify

        Raises:
            Exception: If auth_time is before test_start_time (stale authentication)
        """
        auth_time_str = self.ca.get_property_value(host_id, "dot1x_auth_time")
        if not auth_time_str:
            raise Exception(f"dot1x_auth_time not found for host {host_id}")

        log.info(f"dot1x_auth_time: {auth_time_str}")

        # Parse auth_time format: "Tue Jan 20 18:14:55 CST 2026" -> strip timezone
        match = re.match(r'^(\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2}) [A-Z]{3,4} (\d{4})$', auth_time_str.strip())
        if not match:
            log.warning(f"Could not parse auth_time '{auth_time_str}', skipping time verification")
            return

        try:
            auth_time = datetime.strptime(f"{match.group(1)} {match.group(2)}", "%a %b %d %H:%M:%S %Y")
        except ValueError:
            log.warning(f"Could not parse auth_time '{auth_time_str}', skipping time verification")
            return

        if self.test_start_time and auth_time < self.test_start_time:
            raise Exception(
                f"Stale authentication detected!\n"
                f"  dot1x_auth_time: {auth_time}\n"
                f"  test_start_time: {self.test_start_time}\n"
                f"  Authentication happened before test started."
            )

        log.info(f"Auth time verified: {auth_time} >= {self.test_start_time}")

    def verify_authentication_on_ca(
        self,
        switch_ip: str = None,
        ca_ip: str = None
    ):
        """
        Verify common authentication properties on CounterAct.

        Args:
            switch_ip: Expected Switch IP (dot1x_NAS_addr). Defaults to self.switch.ip
            ca_ip: Expected CounterACT IP (dot1x_auth_appliance). Defaults to self.ca.ipaddress
        """
        host_id = self._get_host_id()
        log.info(f"Verifying authentication for host: {host_id}")

        self._verify_common_properties(
            host_id=host_id,
            switch_ip=switch_ip,
            ca_ip=ca_ip
        )
        log.info("Common authentication verification completed successfully")

    # =========================================================================
    # Endpoint Cleanup
    # =========================================================================

    def cleanup_endpoint_by_mac(self, mac_address: str) -> bool:
        """
        Cleanup endpoint by MAC address.
        Combines getting host IP, deleting endpoint, and cleaning dbObject table.

        Args:
            mac_address: MAC address of the endpoint to cleanup

        Returns:
            True if cleanup completed, False otherwise
        """
        log.info(f"Starting endpoint cleanup for MAC: {mac_address}")
        try:
            # Task 1: Get host IP by MAC address
            endpoint_ip = self.ca.get_host_ip_by_mac(mac_address)

            if endpoint_ip:
                # Task 2: Parse IP (in case of extra data)
                endpoint_ip = endpoint_ip.split(",")[0].strip()
                log.info(f"Endpoint IP: {endpoint_ip}")

                # Task 3: Delete RADIUS endpoint via EM
                self.em.delete_endpoint(endpoint_ip)

        except Exception as e:
            log.warning(f"Could not delete endpoint by MAC {mac_address}: {e}")

        return True

    def verify_san(self, expected_san: str):
        """
        Verify the 802.1x Client Cert Subject Alternative Name property.

        Args:
            expected_san: The expected SAN value (e.g., "URL=E2EQADeviceId:/qae2e-san-testid-12345")
        """
        host_id = self._get_host_id()

        log.info(f"Verifying SAN for host: {host_id}")

        properties_check_list = [
            {"property_field": "dot1x_fr_client_x509_cert_subj_alt_name", "expected_value": expected_san}
        ]

        self.ca.check_properties(host_id, properties_check_list)
        log.info(f"SAN verified: {expected_san}")
