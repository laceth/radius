import ipaddress
import re

from netmiko import ConnectHandler

from framework.connection.connection_pool import CONNECTION_POOL
from framework.connection.ssh_client import SSHClient
from framework.log.logger import log
from lib.switch.switch_base import SwitchBase

CISCOIOS_TYPE = "cisco_ios"


class CiscoIOS(SwitchBase, SSHClient):
    def __init__(self, ip: str, user_name: str, password: str, port1: str | dict = "fa0/1", port2: str | dict = "fa0/2") -> None:
        super().__init__(ip, user_name, password)
        self.ip = ip
        self.username = user_name
        self.password = password
        self.port1 = CiscoIOS._parse_port_config(port1)
        self.port2 = CiscoIOS._parse_port_config(port2)
        self.device = {
            "device_type": CISCOIOS_TYPE,
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "secret": self.password,
        }
        # Connection is established lazily on first exec_command() call so that
        # object construction (and test parametrization) never blocks or fails
        # due to transient SSH banner errors on the switch.
        self.session = None
        self.is_ipv4 = True
        ip_obj = ipaddress.ip_address(self.ip)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            self.is_ipv4 = False

    @staticmethod
    def _parse_port_config(port_config: str | dict) -> dict:
        """
        Parse port configuration into a dict with 'interface' and 'vlan' keys.

        Args:
            port_config: Either a string (interface name) or dict with 'interface' and optional 'vlan'

        Returns:
            Dict with 'interface' (normalized) and 'vlan' (int or None) keys
        """
        if isinstance(port_config, dict):
            interface = port_config.get('interface', '')
            vlan = port_config.get('vlan')
        else:
            interface = port_config
            vlan = None

        return {
            'interface': CiscoIOS.normalize_interface(interface),
            'vlan': int(vlan) if vlan is not None else None
        }

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

    def _execute(self, cmd, timeout=30, log_output=False):
        log.info(f"Executing command on CiscoIOS: {cmd}")
        if isinstance(cmd, list):
            secrets_in_list = any(isinstance(c, str) and self._is_secret_cmd(c) for c in cmd)
            output = self.session.send_config_set(cmd, cmd_verify=not secrets_in_list, read_timeout=timeout)
        else:
            output = self.session.send_command(cmd, expect_string=r"#", read_timeout=timeout)
        
        if log_output:
            log.info(f"Command output:")
            for line in output.strip().split('\n'):
                log.info(f"  {line}")            
        
        return output

    def exec_command(self, cmd, timeout=30, log_output=False):
        for attempt in range(2):
            try:
                self.session = CONNECTION_POOL.get(self.get_conn_key(), self._create_connection)
                return self._execute(cmd, timeout, log_output)
            except Exception as e:
                if attempt == 0:
                    log.warning(
                        f"Switch SSH error on attempt {attempt + 1} "
                        f"(connection may have dropped), reconnecting: {e!r}"
                    )
                    # Evict the broken session from the pool so get() recreates it
                    CONNECTION_POOL.evict(self.get_conn_key())
                else:
                    raise

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

    def _is_secret_cmd(self, cmd: str) -> bool:
        cmd_l = cmd.strip().lower()
        return cmd_l.startswith("key ") or (" server-key " in cmd_l)
