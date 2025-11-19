from framework.log.logger import log


class Radius:
    version = "1.0.0"
    platform = None

    def __init__(self, platform, version="1.0.0"):
        self.platform = platform
        self.version = version

    def exec_cmd(self, command: str, timeout: int = 15) -> str:
        return self.platform.exec_command(command, timeout)

    def get_radius_status(self) -> str:
        command = "fstool dot1x status"
        log.info(self.exec_cmd(command))
        return True
