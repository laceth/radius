from abc import ABC, abstractmethod


class PassthroughBase(ABC):
    def __init__(self, ip: str, user_name: str, password: str, mac: str) -> None:
        self.ip = ip
        self.username = user_name
        self.password = password
        self.mac = mac

    @abstractmethod
    def execute_command(self, command, is_ps=True):
        pass

