import ipaddress
from netmiko import ConnectHandler

from lib.switch.switch_base import SwitchBase

CISCOIOS_TYPE = "cisco_ios"


class CiscoIOS(SwitchBase):

    def __init__(self, ip: str, user_name: str, password: str, src_port: str = "gi0/1", dst_port: str = "gi0/1") -> None:
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

    def exec_command(self, command: str, timeout: int = 15) -> str:
        output = self.session.send_command(command, delay_factor=2, max_loops=timeout)
        return output
