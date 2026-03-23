import copy
import ipaddress
import os
import re
import tempfile
import time
from datetime import datetime
from typing import Union, cast
from framework.ca_log_handler.remote_log_streamer import RemoteLogStreamer
from framework.log.logger import log
from lib.ca.ca_common_base import CounterActBase
from lib.ca.em import EnterpriseManager
from lib.passthrough.enums import AuthenticationStatus
from lib.passthrough.lan_profile_builder import LanProfile
from lib.passthrough.passthrough_base import PassthroughBase
from lib.plugin.radius.radius import Radius
from lib.plugin.radius.radius_plugin_settings import RadiusPluginSettings
from lib.switch.cisco_ios import CiscoIOS
from lib.switch.radius_factory import RadiusFactory
from lib.utils.vlan_mapping import get_ip_range_from_vlan
from tests.fs_test_common_base.test_base import FSTestCommonBase

# CONSTANTS
DOT1X_LOG_PATH = "/usr/local/forescout/log/plugin/dot1x/dot1x.log"
RADIUSD_LOG_PATH = "/usr/local/forescout/log/plugin/dot1x/radiusd.log"

DEFAULT_RADIUS_POLICY_MAC_FIELDS = [
    {
        "EXPR_TYPE": "SIMPLE",
        "CONDITION": {
            "EMPTY_LIST_VALUE": "false",
            "FIELD_NAME": "mac",
            "LABEL": "MAC Address",
            "LEFT_PARENTHESIS": "0",
            "LOGIC": "AND",
            "RET_VALUE_ON_UKNOWN": "IRRESOLVED",
            "RIGHT_PARENTHESIS": "0",
            "FILTER": {
                "CASE_SENSITIVE": "false",
                "TYPE": "equals",
                "VALUE": {
                    "VALUE2": "0050568513ca"
                }
            }
        }
    }
]


class RadiusTestBase(FSTestCommonBase):
    DEFAULT_RADIUS_SECRET = "aristo"
    DEFAULT_RADIUS_SETTINGS = RadiusPluginSettings()
    configure_radius_settings_in_test = False
    AD_DOMAIN_CONFIGS = [
        {
            "ad_domain": "txqalab.forescout.local",
            "ad_ud_user": "administrator",
            "ad_secret": "aristo",
        },
        {
            "ad_domain": "txqalab2.txqalab.forescout.local",
            "ad_ud_user": "admin",
            "ad_secret": "aristo",
        },
        {
            "ad_domain": "txqalab3.txqalab.forescout.local",
            "ad_ud_user": "administrator",
            "ad_secret": "aristo",
        },
    ]

    ad_config1: dict = {}
    ad_config2: dict = {}
    ad_config3: dict = {}

    def __init__(self, ca, em, radius, switch, passthrough, version="1.0.0"):
        self.ca = cast(CounterActBase, ca)
        self.em = cast(EnterpriseManager, em)
        self.version = version
        self.dot1x = cast(Radius, radius)
        self.switch = cast(CiscoIOS, switch)
        self.passthrough = cast(PassthroughBase, passthrough)
        self.nicname = self.passthrough.nicname
        self.rf = RadiusFactory(default_secret=self.DEFAULT_RADIUS_SECRET)
        self.test_start_time = None
        self.host_id_auth_time = set()
        self.host_id = None
        self._last_known_ip = None
        self.dot1x_plugin_log_collector = None
        self.radiusd_log_collector = None
        # dummy for injection
        self.test_log_dir: str = ""

    def suite_setup(self):
        # suite level setup, runs once before all tests in the suite
        log.info("set up radius test suite")
        pass

    def suite_teardown(self):
        # suite level teardown, runs once after all tests in the suite
        log.info("teardown radius suite")
        self.rf.teardown(self.switch, port=self.switch.port1['interface'], radius_server_ip=self.ca.ipaddress)

    def do_setup(self):
        # set up remote log streaming for both dot1x plugin logs and radiusd logs
        log.info("Starting collecting logs from %s for log file: %s" % (self.ca.ipaddress, DOT1X_LOG_PATH))
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        full_path = os.path.join(self.test_log_dir, f"{self.__class__.__name__}_dot1x_{timestamp}.log")
        self.dot1x_plugin_log_collector = RemoteLogStreamer(
            remote_host=self.ca.ipaddress,
            username=self.ca.username,
            password=self.ca.password,
            local_log_file_path=full_path,
            remote_log_path=DOT1X_LOG_PATH
        )
        self.dot1x_plugin_log_collector.start()
        log.info("Starting collecting logs from %s for log file: %s" % (self.ca.ipaddress, RADIUSD_LOG_PATH))
        full_path = os.path.join(self.test_log_dir, f"{self.__class__.__name__}_radiusd_{timestamp}.log")
        self.radiusd_log_collector = RemoteLogStreamer(
            remote_host=self.ca.ipaddress,
            username=self.ca.username,
            password=self.ca.password,
            local_log_file_path=full_path,
            remote_log_path=RADIUSD_LOG_PATH
        )
        self.radiusd_log_collector.start()

        log.info("Radius Common Setup")
        self.log_test_devices()

        # Record test start time
        self.test_start_time = datetime.now()
        log.info(f"Test start time: {self.test_start_time}")

        self.build_ad_config()
        if self.ad_config1:
            self.dot1x.add_auth_source(self.ad_config1["ad_name"], self.ad_config1["ad_ud_user"])
            self.dot1x.join_domain(self.ad_config1["ad_name"], self.ad_config1["ad_ud_user"], self.ad_config1["ad_secret"])
            self.dot1x.set_null(self.ad_config1["ad_name"])
        if not self.configure_radius_settings_in_test:
            self.configure_radius_settings()

        # Cleanup any existing endpoint before test
        self.cleanup_endpoint_by_mac(self.passthrough.mac, timeout=0)

        # Get VLAN and IP range from switch port config
        vlan = self.switch.port1['vlan']
        target_ip_range = get_ip_range_from_vlan(vlan) if vlan else None
        if target_ip_range:
            log.info(f"Target IP range {target_ip_range} derived from VLAN {vlan}")

        # Setup switch RADIUS configuration
        self.rf.setup(
            self.switch,
            port=self.switch.port1['interface'],
            radius_server_ip=self.ca.ipaddress,
            radius_secret=self.DEFAULT_RADIUS_SECRET,
            mab=False,
            vlan=vlan,
        )

    def radius_special_setup(self):
        log.info("radius special setup")

    def do_teardown(self):
        log.info("radius common teardown")
        if self.dot1x_plugin_log_collector is not None:
            self.dot1x_plugin_log_collector.stop()
        if self.radiusd_log_collector is not None:
            self.radiusd_log_collector.stop()

    # =========================================================================
    # Common Helpers
    # =========================================================================
    @property
    def testCaseId(self) -> str:
        m = re.match(r'^TC_(\d+)_', self.__class__.__name__)
        return f"TC-{m.group(1)}" if m else "UNKNOWN"

    def log_test_devices(self):
        log.info(f"Radius Server IP: {self.ca.ipaddress}")
        if self.switch.ip:
            log.info(f"Switch IP: {self.switch.ip}")
        if self.passthrough.mac:
            log.info(f"Passthrough Management IP: {self.passthrough.ip}")
            log.info(f"Passthrough MAC: {self.passthrough.mac}")

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

    # =========================================================================
    # AD Domain Mapping Helpers
    # =========================================================================
    def build_ad_config(self):
        """
        Build AD config map using static domain configs and ad_name resolved from CA devinfo.

        Gets self.ad_config1, self.ad_config2, self.ad_config3 with ad_name/ad_ud_user/ad_secret/ad_domain.
        """
        self.ad_config1 = {}
        self.ad_config2 = {}
        self.ad_config3 = {}
        ad_domain_name_mapping = self.ca.get_ad_domain_name_mapping()

        for idx, ad_domain_config in enumerate(self.AD_DOMAIN_CONFIGS):
            ad_domain = ad_domain_config.get("ad_domain")
            ad_name = ad_domain_name_mapping.get(ad_domain, [None])[0]
            if not ad_name:
                log.warning(f"No ad_name defined for ad_domain '{ad_domain}' in User Directory.")
                continue

            config = {
                "ad_name": ad_name,
                "ad_ud_user": ad_domain_config.get("ad_ud_user"),
                "ad_secret": ad_domain_config.get("ad_secret"),
                "ad_domain": ad_domain,
            }
            setattr(self, f"ad_config{idx + 1}", config)
        return

    # =========================================================================
    # LAN Profile Management
    # =========================================================================

    def configure_lan_profile(
        self,
        lan_profile: LanProfile = None,
        remote_profiles_path: str = None,
    ):
        """
        Configure LAN profile on the Windows endpoint using a ``LanProfile`` builder.

        The XML is generated on-the-fly, written to a temp file, copied to the
        remote machine, and applied via ``netsh lan``.

        Args:
            lan_profile: A ``LanProfile`` instance whose ``to_xml()`` will be used.
            remote_profiles_path: Remote directory for profiles. Default: C:\\Profiles
        """
        if lan_profile is None:
            raise ValueError("lan_profile must be provided")

        remote_dir = remote_profiles_path or r"C:\Profiles"
        remote_filename = "lan_profile.xml"

        log.info(f"Configuring LAN profile (builder) on {self.passthrough.ip}")
        xml_content = lan_profile.to_xml()
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-8")
        try:
            tmp.write(xml_content)
            tmp.close()
            remote_path = f"{remote_dir}\\{remote_filename}"
            self.passthrough.copy_file_to_remote(tmp.name, remote_path)
            self.passthrough.delete_lan_profile(self.nicname)
            self.passthrough.add_lan_profile(remote_path, self.nicname)
        finally:
            try:
                os.unlink(tmp.name)
            except FileNotFoundError:
                # Best-effort cleanup: file already gone is fine.
                pass
            except PermissionError as exc:
                # Do not mask main errors, but log cleanup issues.
                log.warning(f"Failed to delete temporary LAN profile file {tmp.name}: {exc}")

    # =========================================================================
    # NIC Management
    # =========================================================================

    def toggle_nic(self):
        """Toggle NIC to trigger re-authentication."""
        # Update test start time before triggering authentication
        self.test_start_time = datetime.now()
        log.info(
            f"Toggling NIC to trigger re-authentication (updated test_start_time: {self.test_start_time}) "
            f"on {self.passthrough.ip}"
        )
        self.passthrough.toggle_nic(self.nicname)

    def disable_nic(self):
        """Disable the NIC."""
        self.passthrough.disable_nic(self.nicname)

    def enable_nic(self):
        """Enable the NIC."""
        # Update test start time before triggering authentication
        self.test_start_time = datetime.now()
        log.info(
            f"Enabling NIC (updated test_start_time: {self.test_start_time}) "
            f"on {self.passthrough.ip}"
        )
        self.passthrough.enable_nic(self.nicname)

    # =========================================================================
    # Plugin readiness
    # =========================================================================

    def wait_for_dot1x_ready(self, timeout: int = 300, interval: int = 10) -> None:
        """
        Block until the 802.1X plugin is fully operational.

        Should be called in the test *after* all configuration / restart
        calls and *before* the step that actually needs the plugin
        (e.g. ``toggle_nic``).

        Args:
            timeout: Maximum wait in seconds.
            interval: Seconds between polls.
        """
        self.dot1x.wait_until_running(timeout=timeout, interval=interval)

    # =========================================================================
    # Assertions
    # =========================================================================

    def assert_dot1x_plugin_running(self, message: str = "802.1X plugin should be running"):
        """
        Assert that the 802.1X plugin is running.

        Args:
            message: Custom assertion message

        Raises:
            AssertionError: If the plugin is not running
        """
        assert self.dot1x.dot1x_plugin_running(), message

    def assert_nic_authentication_status(
            self, expected_status: Union[AuthenticationStatus, str] = AuthenticationStatus.SUCCEEDED, timeout: int = 90
    ):
        """
        Assert NIC reaches expected authentication status.

        Args:
            expected_status: Expected authentication status
            timeout: Maximum time to wait in seconds
        """
        self.passthrough.wait_for_nic_authentication(self.nicname, expected_status=expected_status, timeout=timeout)

    def verify_nic_ip_in_range(self, timeout: int = 90):
        """
        Wait for NIC to get an IP address in the target VLAN range.
        The IP range is derived from the switch port's VLAN configuration.
        Stores the assigned IP in self._last_known_ip for use by _get_host_id().

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            The IP address that was assigned

        Raises:
            AssertionError: If NIC does not get IP in range within timeout
            ValueError: If VLAN is not configured or IP range cannot be determined
        """
        vlan = self.switch.port1['vlan']
        if not vlan:
            raise ValueError("VLAN is not configured in switch port1 config")

        ip_range = get_ip_range_from_vlan(vlan)
        if not ip_range:
            raise ValueError(f"Could not determine IP range for VLAN {vlan}")

        ip = self.passthrough.wait_for_nic_ip_in_range(self.nicname, ip_range, timeout=timeout)
        self._last_known_ip = ip
        return ip

    def assert_authentication_and_ip_in_range(
            self,
            expected_status: Union[AuthenticationStatus, str] = AuthenticationStatus.SUCCEEDED,
            auth_timeout: int = 90,
            ip_timeout: int = 60
    ):
        """
        Assert NIC authentication succeeds and gets IP in target VLAN range.

        Args:
            expected_status: Expected authentication status
            auth_timeout: Maximum time to wait for authentication
            ip_timeout: Maximum time to wait for IP assignment

        Returns:
            The IP address that was assigned
        """
        self.assert_nic_authentication_status(expected_status=expected_status, timeout=auth_timeout)
        return self.verify_nic_ip_in_range(timeout=ip_timeout)

    def verify_nic_has_no_ip_in_range(self):
        """
        Verify NIC does NOT have an IP address in the target VLAN range.
        This is used to verify that authentication rejection prevents IP assignment.

        Raises:
            AssertionError: If NIC has an IP address in the VLAN range
        """
        vlan = self.switch.port1['vlan']
        if not vlan:
            raise ValueError("VLAN is not configured in switch port1 config")

        ip_range = get_ip_range_from_vlan(vlan)
        if not ip_range:
            raise ValueError(f"Could not determine IP range for VLAN {vlan}")

        current_ip = self.passthrough.get_nic_ip(self.nicname)
        if current_ip:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                if ipaddress.ip_address(current_ip) in network:
                    raise AssertionError(
                        f"NIC '{self.nicname}' has IP '{current_ip}' in VLAN range '{ip_range}' "
                        f"- expected no IP in range after authentication failure"
                    )
            except ValueError:
                pass  # IP parsing failed, consider it as "no valid IP"

        log.info(f"Verified NIC '{self.nicname}' has no IP in VLAN range '{ip_range}'")

    def _get_host_id(self) -> str:
        """
        Get host ID (IP address) for the endpoint.

        Priority:
        1. IP stored by wait_for_nic_ip_in_range() — guaranteed in correct VLAN range.
        2. Current NIC IP — what the CA sees right now (works for accept and reject).
        3. MAC-based lookup from CA with VLAN range preference as last resort.

        Returns:
            Host ID/IP address for the endpoint
        """
        if self._last_known_ip:
            log.info(f"Using stored VLAN IP {self._last_known_ip} for host identification")
            return self._last_known_ip

        # Try current NIC IP — the CA associates properties with whatever IP the host has
        # Skip APIPA (169.254.x) and multicast (224.x+) as the CA won't track hosts under those
        try:
            current_ip = self.passthrough.get_nic_ip(self.nicname)
            if current_ip:
                try:
                    addr = ipaddress.ip_address(current_ip)
                    if not addr.is_multicast and not addr.is_link_local:
                        log.info(f"Using current NIC IP {current_ip} for host identification")
                        return current_ip
                    else:
                        log.info(f"Skipping NIC IP {current_ip} (multicast/link-local)")
                except ValueError:
                    pass
        except Exception:
            pass

        # Last resort: MAC lookup on CA with VLAN range preference
        preferred_range = None
        try:
            vlan = self.switch.port1.get('vlan')
            if vlan:
                preferred_range = get_ip_range_from_vlan(vlan)
        except Exception:
            pass

        return self.ca.get_host_ip_by_mac(self.passthrough.mac, preferred_range=preferred_range)

    def _get_dot1x_host_id(self) -> str:
        """Return the best identifier for dot1x_* properties.

        In many CounterACT setups, dot1x_* properties are attached to the MAC-based
        host record (not the current DHCP IP). Using the MAC avoids intermittent
        failures where IP-based lookups return None.
        """
        mac = getattr(self.passthrough, "mac", None)
        if mac:
            return mac
        return self._get_host_id()

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

        # Debug: dump all dot1x properties
        self._dump_dot1x_properties(host_id)

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

    def verify_pre_admission_rule(self, rule_priority: int = 1, auth_state: str = "Access-Accept"):
        """
        Verify that authentication was processed by the expected pre-admission rule.

        Args:
            rule_priority: The priority number of the pre-admission rule. Default: 1
            auth_state: Expected auth state. Default: "Access-Accept"
        """
        if not self.host_id:
            # Keep host_id for other checks; use MAC for dot1x_* properties.
            self.host_id = self._get_host_id()
        dot1x_host_id = self._get_dot1x_host_id()
        # Debug: dump all dot1x properties (only on first verification)
        self._dump_dot1x_properties(dot1x_host_id)

        expected_source = f"Pre-Admission rule {rule_priority}"
        log.info(f"Verifying pre-admission rule for host: {dot1x_host_id}")

        # First verify auth_state is correct, then check auth_source
        # If auth_state is Access-Reject, auth_source will be None
        properties_check_list = [
            {"property_field": "dot1x_auth_state", "expected_value": auth_state},
            {"property_field": "dot1x_auth_source", "expected_value": expected_source}
        ]

        self.ca.check_properties(dot1x_host_id, properties_check_list)
        log.debug(f"Pre-admission rule verified: {expected_source}")

    def _dump_dot1x_properties(self, host_id: str):
        """Debug: dump all dot1x properties for a host (once per authentication event)."""
        # Get current auth_time to track unique authentication events
        try:
            auth_time = self.ca.get_property_value(host_id, "dot1x_auth_time")
            auth_key = (host_id, auth_time)

            if auth_key in self.host_id_auth_time:
                return

            output = self.ca.exec_command(f"fstool hostinfo {host_id} | grep dot1x")
            log.info(f"All dot1x properties for {host_id} (auth_time: {auth_time}):")
            for line in output.strip().split('\n'):
                log.info(f"  {line}")
            self.host_id_auth_time.add(auth_key)
        except Exception as e:
            log.warning(f"Failed to dump dot1x properties: {e}")

    def verify_wired_properties(self, nas_port_id: str = None):
        """
        Verify wired-specific authentication properties on CounterAct.

        Args:
            nas_port_id: Expected NAS Port ID (dot1x_NASPortIdStr). Defaults to self.switch.port1['interface']
        """
        if not self.host_id:
            # Keep host_id for other checks; use MAC for dot1x_* properties.
            self.host_id = self._get_host_id()
        dot1x_host_id = self._get_dot1x_host_id()
        # Debug: dump all dot1x properties (only on first verification)
        self._dump_dot1x_properties(dot1x_host_id)

        nas_port_id = nas_port_id or self.switch.port1['interface']
        log.info(f"Verifying wired properties for host: {dot1x_host_id}")

        properties_check_list = [
            {"property_field": "dot1x_NASPortIdStr", "expected_value": nas_port_id}
        ]

        self.ca.check_properties(dot1x_host_id, properties_check_list)
        log.debug(f"Wired properties verified: NAS Port ID = {nas_port_id}")

    def verify_wireless_properties(self, nas_identifier: str = None, nas_port_id: str = None):
        """
        Verify wireless-specific authentication properties on CounterAct.

        Args:
            nas_identifier: Expected NAS Identifier (dot1x_NAS_Identifier). Example: "cisco9800_vlan1824"
            nas_port_id: Expected NAS Port ID (dot1x_NASPortIdStr). Example: "capwap_90000008"
        """
        if not self.host_id:
            self.host_id = self._get_host_id()
        # Debug: dump all dot1x properties (only on first verification)
        self._dump_dot1x_properties(self.host_id)
        log.info(f"Verifying wireless properties for host: {self.host_id}")

        properties_check_list = [
            {"property_field": "dot1x_NAS_Identifier", "expected_value": nas_identifier},
            {"property_field": "dot1x_NASPortIdStr", "expected_value": nas_port_id},
        ]

        self.ca.check_properties(self.host_id, properties_check_list)
        log.info(f"Wireless properties verified: NAS Identifier = {nas_identifier}, NAS Port ID = {nas_port_id}")

    def _verify_auth_time(self, host_id: str):
        """
        Verify dot1x_auth_time is after test_start_time.

        Args:
            host_id: Host ID to verify

        Raises:
            Exception: If auth_time is before test_start_time (stale authentication)
        """
        property_field = "dot1x_auth_time"
        auth_time_str = self.ca.get_property_value(host_id, property_field)
        if not auth_time_str:
            raise Exception(f"{property_field} not found for host {host_id}")

        log.debug(f"{property_field}: {auth_time_str}")

        # Parse auth_time format: "Tue Jan 20 18:14:55 CST 2026" -> strip timezone
        match = re.match(r'^(\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2}) [A-Z]{3,4} (\d{4})$', auth_time_str.strip())
        if not match:
            log.warning(f"Could not parse {property_field} '{auth_time_str}', skipping time verification")
            return

        try:
            auth_time = datetime.strptime(f"{match.group(1)} {match.group(2)}", "%a %b %d %H:%M:%S %Y")
        except ValueError:
            log.warning(f"Could not parse {property_field} '{auth_time_str}', skipping time verification")
            return

        if self.test_start_time and auth_time < self.test_start_time:
            raise Exception(
                f"Stale authentication detected!\n"
                f"  {property_field}: {auth_time}\n"
                f"  test_start_time: {self.test_start_time}\n"
                f"  Authentication happened before test started."
            )

        expected_time = self.test_start_time.strftime('%Y-%m-%d %H:%M:%S')
        log.info(f"Property {property_field:30s}: expected>{expected_time:20s}, actual={str(auth_time):20s}, match=True")

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
        if not self.host_id:
            self.host_id = self._get_host_id()
        dot1x_host_id = self._get_dot1x_host_id()
        log.info(f"Verifying authentication for host: {dot1x_host_id}")

        self._verify_common_properties(
            host_id=dot1x_host_id,
            switch_ip=switch_ip,
            ca_ip=ca_ip
        )
        log.info("Common authentication verification completed successfully")

    # =========================================================================
    # Endpoint Cleanup
    # =========================================================================

    def cleanup_endpoint_by_mac(self, mac_address: str, timeout: int = 60) -> bool:
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
            endpoint_ip = self.ca.get_host_ip_by_mac(mac_address, timeout=timeout)

            if endpoint_ip:
                # Task 2: Parse IP (in case of extra data)
                endpoint_ip = endpoint_ip.split(",")[0].strip()
                log.info(f"Endpoint IP: {endpoint_ip}")

                # Task 3: Delete RADIUS endpoint via EM
                self.em.delete_endpoint(endpoint_ip)
                self.host_id = None  # Reset host_id cache after deletion

        except Exception as e:
            log.warning(f"Could not delete endpoint by MAC {mac_address}: {e}")

        return True

    def verify_san(self, expected_san: str):
        """
        Verify the 802.1x Client Cert Subject Alternative Name property.

        Args:
            expected_san: The expected SAN value (e.g., "URL=E2EQADeviceId:/qae2e-san-testid-12345")
        """
        if not self.host_id:
            self.host_id = self._get_host_id()

        dot1x_host_id = self._get_dot1x_host_id()
        properties_check_list = [
            {"property_field": "dot1x_fr_client_x509_cert_subj_alt_name", "expected_value": expected_san}
        ]

        # Prefer the dot1x/MAC-based host record (more reliable for dot1x_* properties),
        # but fall back to the IP-based record if the property is stored there.
        log.info(f"Verifying SAN for host (dot1x id): {dot1x_host_id}")
        try:
            self.ca.check_properties(dot1x_host_id, properties_check_list)
            log.info(f"SAN verified: {expected_san}")
            return
        except Exception as e:
            if dot1x_host_id == self.host_id:
                raise
            log.warning(
                f"SAN check failed on dot1x id '{dot1x_host_id}' ({e}); retrying on IP host id '{self.host_id}'"
            )

        log.info(f"Verifying SAN for host (ip id): {self.host_id}")
        self.ca.check_properties(self.host_id, properties_check_list)
        log.info(f"SAN verified: {expected_san}")

    def add_dot1x_policy_radius_fr_client_x509_cert_subj_alt_name(self, match_type, value, match_case=False,
                                                                  inner_not=False):
        """
            Add a condition to the policy to check the 802.1x Client Cert Subject Alternative Name property.
            type: The type of match (e.g., "equals", "contains", "startswith", "endswith")
            value: The value to match against the SAN property (e.g., "1.1.2" for endswith)
            match_case: Whether the match should be case sensitive. Default is False.
            inner_not: Whether to apply NOT operator to the inner condition. Default is False.
            Returns: Policy name(str)
        """
        # CounterACT policy import expects specific FILTER TYPE values (typically lowercase).
        # Some tests historically use UI-like strings (e.g. "Any Value"/"AnyValue"/"Contains").
        # Normalize to supported XML values to avoid import failures.
        raw_match_type = str(match_type or "").strip()
        normalized_key = re.sub(r"\s+", "", raw_match_type).lower()  # e.g. "Any Value" -> "anyvalue"
        match_type_map = {
            "equals": "equals",
            "contains": "contains",
            "startswith": "startswith",
            "endswith": "endswith",
            "matches": "matches",
            "matchesexpression": "matchesexpression",
            # Map UI-style any-value strings to a supported operator.
            # In this codebase, callers still provide a concrete `value` to match,
            # so `contains` preserves intent and is supported by policy import.
            "anyvalue": "contains",
        }

        match_type = match_type_map.get(normalized_key, raw_match_type.lower() or "contains")

        fields = copy.deepcopy(DEFAULT_RADIUS_POLICY_MAC_FIELDS)
        fields[0]["CONDITION"]["FILTER"]["VALUE"]["VALUE2"] = self.passthrough.mac
        fields.append(
            {
                "EXPR_TYPE": "SIMPLE",
                "CONDITION": {
                    "EMPTY_LIST_VALUE": "false",
                    "FIELD_NAME": "dot1x_fr_client_x509_cert_subj_alt_name",
                    "LABEL": "802.1x Client Cert Subject Alternative Name",
                    "LEFT_PARENTHESIS": "0",
                    "LOGIC": "AND",
                    "RET_VALUE_ON_UKNOWN": "IRRESOLVED",
                    "INNER_NOT": str(inner_not).lower(),
                    "RIGHT_PARENTHESIS": "0",
                    "FILTER": {
                        "CASE_SENSITIVE": str(match_case).lower(),
                        "TYPE": match_type,
                        "VALUE": {
                            "VALUE2": value
                        }
                    }
                }
            }
        )
        policy_name = "policy_condition_dot1x_fr_client_x509_cert_subj_alt_name"
        self.em.simple_policy_condition(
            "dot1xSimplePolicyCondition.xml",
            policy_name,
            fields,
            allow_unknown_ip=True,
        )
        return policy_name

    def add_dot1x_policy_eap_type(self, eap_type: str = "EAP-TLS") -> str:
        """
        Add a CounterAct condition policy that matches on 802.1x Authentication Type
        (``dot1x_fr_eap_type``) for the endpoint under test.

        The policy uses MAC address + EAP-type as compound condition so it only
        matches the specific test endpoint.

        Args:
            eap_type: Expected EAP type string (e.g. "TTLS", "PEAP", "EAP-TLS").
                      Default: "EAP-TLS".

        Returns:
            str: The created policy name (pass to ``self.ca.check_policy_match()``).
        """
        fields = copy.deepcopy(DEFAULT_RADIUS_POLICY_MAC_FIELDS)
        fields[0]["CONDITION"]["FILTER"]["VALUE"]["VALUE2"] = self.passthrough.mac
        fields.append(
            {
                "EXPR_TYPE": "SIMPLE",
                "CONDITION": {
                    "EMPTY_LIST_VALUE": "false",
                    "FIELD_NAME": "dot1x_fr_eap_type",
                    "LABEL": "802.1x Authentication Type",
                    "LEFT_PARENTHESIS": "0",
                    "LOGIC": "AND",
                    "RET_VALUE_ON_UKNOWN": "IRRESOLVED",
                    "RIGHT_PARENTHESIS": "0",
                    "FILTER": {
                        "CASE_SENSITIVE": "false",
                        "TYPE": "equals",
                        "VALUE": {
                            "VALUE2": eap_type
                        }
                    }
                }
            }
        )
        policy_name = f"Auth_Type_{eap_type}"
        self.em.simple_policy_condition("dot1xSimplePolicyCondition.xml", policy_name, fields)
        return policy_name

    def radius_authorize(
            self,
            iscoa=True,
            vlan=None,
            attribute_value_pair=None,
            reject=False,
            tunnel_type=13,
            tunnel_medium_type=6,
    ):
        """
        Add a predefined action 'dot1x_authorize' to the policy for RADIUS authorization.

        Args:
            vlan (str): VLAN ID. Defaults to None.
            tunnel_type (int): Tunnel Type. Defaulted to 13.
            tunnel_medium_type (int): Tunnel Medium Type. Defaulted to 6.
            iscoa (bool): Whether IsCOA is enabled. Defaults to True. Force Re-authentication when False
            attribute_value_pair: Additional parameters. elements can be extracted directly from policy xml files
            i.e. ["Cabletron-Protocol-Callable=IP-BR-Callable", "A-ESAM-QOS-Params=111", "Cisco-AVPair=subscriber:command=reauthenticate"]

        Returns:
            str: The name of the created action.
        """
        if attribute_value_pair is None:
            attribute_value_pair = []
        if reject:
            params = ["reject=dummy"]
        else:
            params = [
                f"vlan:{vlan or ''}",
                f"IsCOA:{str(iscoa).lower()}"
            ]
            if vlan is not None:
                params = [
                    f"vlan:{vlan or ''}",
                    f"Tunnel-Private-Group-Id={vlan or ''}",
                    f"Tunnel-Type={tunnel_type}",
                    f"Tunnel-Medium-Type={tunnel_medium_type}",
                    f"IsCOA:{str(iscoa).lower()}"
                ]
        for _iter in attribute_value_pair:
            params.append(_iter)
        value = "&#9;".join(filter(None, params))

        action_name = "dot1x_authorize"  # Predefined action name

        # set condition for mac filter
        fields = copy.deepcopy(DEFAULT_RADIUS_POLICY_MAC_FIELDS)
        fields[0]["CONDITION"]["FILTER"]["VALUE"]["VALUE2"] = self.passthrough.mac

        # Add the serialized action parameters
        action_params = {"authorization": value}
        # Use the simple_action function to create the action
        self.em.simple_policy_action("radiusSimpleAction.xml", action_name, fields, action_name, action_params)
        return action_name

    def verify_policy_match(self, policy_name: str, expected_count: int = 1) -> None:
        """
        Verify that a policy matches expected_count endpoints.
        Timeout/retry/error formatting stays inside the framework.
        """
        # Use EM helper with a longer default to accommodate policy import + HA propagation.
        self.em.verify_policy_match(policy_name, expected_count=expected_count)

    def verify_policy_subrule_match(self, policy_name: str, subrule: str, expected_count: int = 1) -> None:
        """
        Verify MATCH count for a specific subrule (Policy -> subrule).
        """
        self.em.verify_policy_subrule_match(policy_name, subrule=subrule, expected_count=expected_count)

    def get_policy_stats(self, policy_name: str, timeout: int = 30, retry_interval: int = 5) -> dict:
        """
        Return policy stats aggregated across nodes (HA-safe).
        Supports optional '-> subrule' lines and returns both MATCH/UNMATCH.

        Output examples:
        10.100.49.78: PolicyName : MATCH : 1
        10.100.49.78: PolicyName : UNMATCH : 15
        10.16.177.82: Test Script -> d  : MATCH : 26
        10.16.177.82: Test Script -> tt : MATCH : 7
        """
        start_time = time.time()
        cmd = f"fstool oneach fstool npstats | grep -F '{policy_name}' || true"

        last = ""
        while time.time() - start_time < timeout:
            # IMPORTANT: execute on EM  exec_command
            out = self.em.exec_command(cmd, timeout=30, log_command=True, log_output=True).strip()
            if out:
                last = out
                break
            time.sleep(retry_interval)

        pat = re.compile(
            r"^(?:(?P<node>\S+):\s*)?"
            r"(?P<policy>.+?)(?:\s*->\s*(?P<subrule>[^:]+))?\s*:\s*"
            r"(?P<kind>MATCH|UNMATCH)\s*:\s*(?P<count>\d+)\s*$"
        )

        stats = {
            # totals across ALL lines (including subrules)
            "match_total": 0,
            "unmatch_total": 0,

            # base-only totals (lines WITHOUT -> subrule)
            "match_base": 0,
            "unmatch_base": 0,
            "saw_base_line": False,

            # per-subrule totals
            "by_subrule": {},  # subrule -> {"match": x, "unmatch": y}

            "raw": last,
        }

        for line in (last.splitlines() if last else []):
            m = pat.match(line.strip())
            if not m:
                continue

            kind = m.group("kind")
            cnt = int(m.group("count"))
            sub = (m.group("subrule") or "").strip() or None

            # totals
            if kind == "MATCH":
                stats["match_total"] += cnt
            else:
                stats["unmatch_total"] += cnt

            # base vs subrule
            if sub is None:
                stats["saw_base_line"] = True
                if kind == "MATCH":
                    stats["match_base"] += cnt
                else:
                    stats["unmatch_base"] += cnt
            else:
                bucket = stats["by_subrule"].setdefault(sub, {"match": 0, "unmatch": 0})
                if kind == "MATCH":
                    bucket["match"] += cnt
                else:
                    bucket["unmatch"] += cnt

        return stats
