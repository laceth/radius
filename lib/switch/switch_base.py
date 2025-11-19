from abc import ABC, abstractmethod


class SwitchBase(ABC):
    def __init__(self, ip: str, user_name: str, password: str):
        self.ip = ip
        self.username = user_name
        self.password = password
