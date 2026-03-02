from abc import ABC, abstractmethod


class PassthroughBase(ABC):
    def __init__(self, ip: str, user_name: str, password: str, mac: str, nicname: str = "pciPassthru0") -> None:
        self.ip = ip
        self.username = user_name
        self.password = password
        self.mac = mac
        self.nicname = nicname

    @abstractmethod
    def execute_command(self, command, is_ps=True):
        pass

    @abstractmethod
    def wait_for_nic_ip_in_range(self, nicname, ip_range, timeout):
        pass

    @abstractmethod
    def wait_for_nic_authentication(self, nicname, expected_status, timeout):
        pass

    @abstractmethod
    def get_nic_ip(self, nicname):
        pass


