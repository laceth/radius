"""
Base class for MAB (MAC Authentication Bypass) functional tests.

MAB is used for endpoints that don't have 802.1X supplicants (e.g., printers, IP phones).
The switch authenticates the endpoint based on its MAC address via RADIUS.
"""
import os
import tempfile
from datetime import datetime
from typing import Union

from framework.log.logger import log
from lib.passthrough.lan_profile_builder import LanProfile
from lib.plugin.radius.enums import RadiusAuthStatus
from lib.plugin.radius.models.mab_config import MABConfig
from lib.plugin.radius.models.mar_entry import MAREntry, MAR_CSV_HEADER
from lib.utils.csv import write_csv
from lib.utils.mac import normalize_mac, generate_unique_random_macs
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
        self.cleanup_endpoint_by_mac(self.passthrough.mac, timeout=0)

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
        self.host_id = normalize_mac(self.nic_mac)
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

        # Always identify the host by MAC — immune to IP-address drift between
        # the NIC's DHCP lease and the IP CounterAct has on record.
        host_id = normalize_mac(self.nic_mac) if self.nic_mac else self._get_host_id()
        log.info(f"Verifying MAB/MAR authentication for host: {host_id}")

        # Set defaults from test configuration
        switch_ip = switch_ip or self.switch.ip
        ca_ip = ca_ip or self.ca.ipaddress


        # Normalize MAC to lowercase without separators for dot1x_user check
        normalized_mac = normalize_mac(self.nic_mac) if self.nic_mac else ""

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

    def verify_radius_imposed_auth(self, expected_reply_message: str):
        """Verify the dot1x_ass_restrictions property contains the expected Reply-Message."""
        host_id = self.host_id or self._get_host_id()
        self.ca.check_properties(host_id, [
            {
                "property_field": "dot1x_ass_restrictions",
                "expected_value": f"Reply-Message={expected_reply_message}",
            }
        ])
        log.info(f"Verified RADIUS Imposed Authorization: Reply-Message={expected_reply_message}")

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

    def ensure_mac_not_in_mar(self, mac: str = None):
        """
        Remove MAC from MAR if it exists. No-op if absent.

        Args:
            mac: MAC address to clean up. Defaults to self.nic_mac
        """
        mac = mac or self.nic_mac
        if self.em.mac_exists_in_mar(mac):
            self.em.remove_mac_from_mar(mac)
            log.info(f"Cleaned up MAC {mac} from MAR")
        else:
            log.info(f"MAC {mac} not in MAR, nothing to clean up")

    def bulk_import_mar_entries(self, count: int, comment: str = "bulk_test") -> str:
        """
        Generate random MAR entries, write to a temp CSV, and bulk-import to the EM.

        Args:
            count: Number of random MAR entries to generate and import.
            comment: Comment to set on each generated entry.

        Returns:
            Path to the generated CSV file (caller is responsible for cleanup
            via ``bulk_cleanup_mar``).
        """
        entries = [MAREntry.accept(mac, comment=comment) for mac in generate_unique_random_macs(count)]
        fd, csv_path = tempfile.mkstemp(prefix="mar_bulk_import_", suffix=".csv")
        os.close(fd)
        write_csv(entries, csv_path, MAR_CSV_HEADER)
        log.info(f"Generated {len(entries)} MAR entries to {csv_path}")

        imported = self.em.bulk_import_mar_csv(csv_path)
        log.info(f"Bulk MAR import complete: {imported} entries submitted")
        return csv_path

    def bulk_cleanup_mar(self, csv_path: str) -> None:
        """
        Remove all MAR entries from a previously imported CSV and delete the file.

        Args:
            csv_path: Path to the CSV file used for bulk import.
        """
        if not csv_path or not os.path.isfile(csv_path):
            return
        try:
            removed = self.em.bulk_remove_mar_csv(csv_path)
            log.info(f"Bulk MAR cleanup complete: {removed} entries removed")
        except Exception as e:
            log.warning(f"Bulk MAR cleanup failed: {e}")
        finally:
            os.remove(csv_path)
            log.info(f"Deleted temp CSV: {csv_path}")




