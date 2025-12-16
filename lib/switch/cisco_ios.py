import ipaddress
import re

from netmiko import ConnectHandler

from framework.connection.connection_pool import CONNECTION_POOL
from framework.connection.ssh_client import SSHClient
from framework.log.logger import log
from lib.switch.switch_base import SwitchBase

CISCOIOS_TYPE = "cisco_ios"


class CiscoIOS(SwitchBase, SSHClient):
    def __init__(self, ip: str, user_name: str, password: str, port1: str = "gi0/1", port2: str = "gi0/1") -> None:
        super().__init__(ip, user_name, password)
        self.ip = ip
        self.username = user_name
        self.password = password
        self.port1 = CiscoIOS.normalize_interface(port1)
        self.port2 = CiscoIOS.normalize_interface(port2)
        self.device = {
            "device_type": CISCOIOS_TYPE,
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "secret": self.password,
        }
        self.session = ConnectHandler(**self.device)
        try:
            # Enter privileged exec mode if device opens in user exec ('>')
            self.session.enable()
        except Exception as exc:
            # If no enable is required or fails, continue; config ops will raise if needed
            log.warning(f"CiscoIOS enable not required on {self.ip}: {exc}")
        self.is_ipv4 = True
        ip_obj = ipaddress.ip_address(self.ip)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            self.is_ipv4 = False

    def get_conn_key(self):
        return self.ip

    def _create_connection(self):
        self.device = {
            "device_type": CISCOIOS_TYPE,
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "secret": self.password,
        }
        self.session = ConnectHandler(**self.device)
        try:
            self.session.enable()
        except Exception as exc:
            log.warning(f"CiscoIOS enable not required on {self.ip}: {exc}")
        return self.session

    def _execute(self, cmd, timeout=30):
        log.info(f"Executing command on CiscoIOS: {cmd}")
        if isinstance(cmd, list):
            # Use config mode for multi-line configuration commands
            output = self.session.send_config_set(cmd)
        else:
            output = self.session.send_command(cmd, delay_factor=2, max_loops=timeout)
        return output

    def exec_command(self, cmd, timeout=30):
        self.session = CONNECTION_POOL.get(self.get_conn_key(), self._create_connection)
        return self._execute(cmd, timeout)

    @staticmethod
    def normalize_interface(ifname: str) -> str:
        """Normalize Cisco IOS interface shorthand to canonical names."""
        if ifname is None:
            raise ValueError("Interface name cannot be None")

        s = ifname.strip().lower()
        if not s:
            raise ValueError("Interface name cannot be empty")

        patterns = {
            r"^gi|gig|gbe": "GigabitEthernet",
            r"^fa|fast": "FastEthernet",
            r"^te|teng": "TenGigabitEthernet",
            r"^fo|forty": "FortyGigabitEthernet",
            r"^hundred|^hu": "HundredGigE",
            r"^eth|^e": "Ethernet",
            r"^lo|loop": "Loopback",
            r"^vlan": "Vlan",
        }

        m = re.match(r"([a-zA-Z]+)([\d/]+)", s)
        if not m:
            raise ValueError(f"Invalid Cisco interface format: {ifname}")

        prefix, numbers = m.groups()
        for pat, full in patterns.items():
            if re.match(pat, prefix):
                return f"{full}{numbers}"

        return f"{prefix.capitalize()}{numbers}"
