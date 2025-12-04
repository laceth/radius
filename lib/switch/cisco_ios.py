import ipaddress
from netmiko import ConnectHandler
from framework.connection.connection_pool import CONNECTION_POOL
from framework.connection.ssh_client import SSHClient
from framework.log.logger import log
from lib.switch.switch_base import SwitchBase
CISCOIOS_TYPE = "cisco_ios"


class CiscoIOS(SwitchBase, SSHClient):

    def __init__(self, ip: str, user_name: str, password: str, src_port: str = "gi0/1",
                 dst_port: str = "gi0/1") -> None:
        super().__init__(ip, user_name, password)
        self.ip = ip
        self.username = user_name
        self.password = password
        self.src_port = src_port
        self.dst_port = dst_port
        self.device = {
            "device_type": CISCOIOS_TYPE,
            "ip": self.ip,
            "username": self.username,
            "password": self.password
        }
        self.session = ConnectHandler(**self.device)
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
            "password": self.password
        }
        self.session = ConnectHandler(**self.device)
        return self.session

    def _execute(self, cmd, timeout=30):
        log.info(f"Executing command on CiscoIOS: {cmd}")
        output = self.session.send_command(cmd, delay_factor=2, max_loops=timeout)
        return output

    def exec_command(self, cmd, timeout=30):
        self.session = CONNECTION_POOL.get(self.get_conn_key(), self._create_connection)
        return self._execute(cmd, timeout)
