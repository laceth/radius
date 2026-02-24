import ipaddress
import re
import time
from typing import Dict, List, Optional

from framework.log.logger import log
from lib.ca.ca_common_base import CounterActBase

# Command
REMOVE_ENDPOINT_CMD = "fstool cliapi host remove %s"
GET_HOSTINFO_BASE_CMD = "fstool hostinfo %s"
PROPERTY_CHECK_COMMAND = "fstool hostinfo %s | grep %s,"

# Matches common MAC formats: aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabbccddeeff
_MAC_RE = re.compile(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$|^[0-9a-fA-F]{12}$')


def _is_valid_mac(value: str) -> bool:
    """Return True if *value* looks like a MAC address."""
    return bool(_MAC_RE.match(value))


class CouterActAppliance(CounterActBase):
    def __int__(self, ca: CounterActBase):
        super().__init__()

    def _resolve_id(self, id: str) -> str:
        """
        Resolve the host identifier to an IPv4-based host ID.

        * IPv4 addresses are returned as-is.
        * IPv6 addresses are mapped to their corresponding IPv4 host ID.
        * MAC addresses (colon/dash-separated or 12-hex-char) are returned as-is.
        * Anything else raises ``ValueError``.
        """
        try:
            addr = ipaddress.ip_address(id)
            if isinstance(addr, ipaddress.IPv6Address):
                return self.get_id_by_ipv6(id)
            return id  # IPv4
        except ValueError:
            pass
        if _is_valid_mac(id):
            return id
        raise ValueError(
            f"'{id}' is not a valid IPv4/IPv6 address or MAC address"
        )

    def clear_endpoint_by_id(self, id: str):
        log.info(f"Clearing endpoint with ID: {id}")
        cmd = REMOVE_ENDPOINT_CMD % id
        output = self.exec_command(cmd)
        log.info(f"Command output: {output}")

    def get_id_by_mac(self, mac: str):
        cmd = GET_HOSTINFO_BASE_CMD % mac
        output = self.exec_command(cmd)
        if output == "":
            raise Exception("mac given not found on CA")
        return output.split("\n")[0].split(',')[0]

    def get_id_by_ipv6(self, ip: str):
        output = self.exec_command()
        ipPattern = re.compile('\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}')
        host_ids = re.findall(ipPattern, output)
        if not host_ids:
            raise Exception("failed to retrieve id for ipv6: %s" % ip)
        return host_ids[0]

    def get_property_value(self, id: str, property_field: str) -> Optional[str]:
        """
        Get the value of a property for a host.

        Args:
            id: Host identifier (IP address or MAC address).
            property_field: The property field to retrieve.

        Returns:
            Property value or None if not found.

        Raises:
            ValueError: If id is not a valid IPv4/IPv6 address or MAC address.
        """
        id = self._resolve_id(id)
        if not property_field or not id:
            raise Exception("property_field and id are required")

        output = self.exec_command(PROPERTY_CHECK_COMMAND % (id, property_field))
        parts = output.split(", ")
        return parts[3] if len(parts) > 3 else None

    def _property_check(self, id: str, property_field: str, expected_value: str, resolved_by: str = "", timeout: int = 60, case_insensitive: bool = False):
        """
        Check if a property of a host matches the expected value.
        Waits up to `timeout` seconds for the property to have the expected value.

        args:
            id: Host identifier (IP address or MAC address).
            property_field: The property field to check.
            expected_value: The expected value of the property field.
            resolved_by: Optional plugin name that should have resolved the property.
            timeout: Maximum time in seconds to wait for the property to match (default: 60).
            case_insensitive: If True, perform case-insensitive comparison (default: False).
        returns:
            Tuple of (result: bool, actual_value: str, actual_resolved_by: str)

        Raises:
            ValueError: If id is not a valid IPv4/IPv6 address or MAC address.
        """

        id = self._resolve_id(id)
        if not property_field or not id:
            raise Exception("property_field and id are required")

        start_time = time.time()
        field_value = None
        resolved_by_plugin = None
        res = False

        while time.time() - start_time < timeout:
            try:
                output = self.exec_command(PROPERTY_CHECK_COMMAND % (id, property_field))
                field_value = output.split(", ")[3] if len(output.split(", ")) > 4 else None
                resolved_by_plugin = re.search(r'\((\w+)@', output).group(1) if re.search(r'\((\w+)@', output) else None
            except RuntimeError as e:
                # grep returns exit code 1 when no match found - this is expected when property doesn't exist yet
                log.debug(f"Property '{property_field}' not found yet: {e}")
                field_value = None
                resolved_by_plugin = None

            # Perform case-insensitive comparison if requested
            if case_insensitive and expected_value and field_value:
                res = expected_value.lower() == field_value.lower()
            else:
                res = expected_value == field_value
            if resolved_by != "":
                res &= resolved_by == resolved_by_plugin

            if res:
                return res, field_value, resolved_by_plugin

            log.info(f"Property '{property_field}' not yet '{expected_value}' (current: '{field_value}'), retrying...")
            time.sleep(1)

        return res, field_value, resolved_by_plugin

    def check_properties(self, id: str, properties_check_list):
        """
        Check multiple properties of a host.
        args:
            id: Host identifier (IP address or MAC address).
            properties_check_list: List of dictionaries with keys 'property_field', 'expected_value', and optional 'resolved_by'
            example:
            properties_check_list = [
                {
                    "property_field": "dhcp_hostname",
                    "expected_value": "AUTOBVT-GIG6GUR",
                    "resolved_by": "dhclass"
                },
                {
                    "property_field": "os_classification_source",
                    "expected_value": "dpl",
                    "resolved_by": "classification"
                },
                {
                    "property_field": "discovery_score",
                    "expected_value": "93",
                    "resolved_by": "classification"
                }
            ]
        """
        log.info(f"Starting property checks for ID: {id}")
        for item in properties_check_list:
            property_field = item.get('property_field')
            expected_value = item.get('expected_value')
            result, actual_value, actual_resolved_by = self._property_check(id=id, **item)
            actual_str = str(actual_value or "")
            log.info(f"Property {property_field:30s}: expected={expected_value:20s}, actual={actual_str:20s}, match={result}")
            
            if not result:
                resolved_by = item.get('resolved_by', '')

                error_msg = (
                    f"Property check failed for '{property_field}':\n"
                    f"  Expected: '{expected_value}'\n"
                    f"  Actual:   '{actual_value}'"
                )
                if resolved_by:
                    error_msg += (
                        f"\n  Expected resolved_by: '{resolved_by}'\n"
                        f"  Actual resolved_by:   '{actual_resolved_by}'"
                    )
                raise Exception(error_msg)
        log.info("All property checks passed")
        return True

    def get_ad_domain_name_mapping(self, domain_filter: Optional[str] = "forescout.local") -> Dict[str, List[str]]:
        """
        Query devinfo for AD domains and return a mapping of ad_domain -> list of ad_name (id).

        Args:
            domain_filter: Optional substring filter for ad_domain (SQL LIKE %filter%).

        Returns:
            Dict mapping ad_domain (field_value) to a list of ad_name (id) values.
        """
        ad_domain_query_base = (
            "SELECT id, field_name, field_value "
            "FROM devinfo "
            "WHERE category='ad' AND field_name='ad_domain'"
        )
        query = ad_domain_query_base
        if domain_filter:
            query += f" AND field_value LIKE '%{domain_filter}%'"

        cmd = f"psql -t -A -F '|' -c \"{query}\""
        output = self.exec_command(cmd, log_output=True, log_command=True)
        ad_domain_name_mapping: Dict[str, List[str]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [part.strip() for part in line.split("|")]
            if len(parts) < 3:
                continue
            ad_name, ad_domain = parts[0], parts[2]    
            ad_domain_name_mapping.setdefault(ad_domain, []).append(ad_name)

        log.info(f"AD domain and ad name mapping retrieved: {ad_domain_name_mapping}")
        return ad_domain_name_mapping
