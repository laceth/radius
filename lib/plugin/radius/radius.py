import time
from framework.log.logger import log
from lib.plugin.radius.radius_base import RadiusBase


class Radius(RadiusBase):

    def exec_cmd(self, command: str, timeout: int = 15) -> str:
        return self.platform.exec_command(command, timeout)

    def dot1x_plugin_running(self) -> bool:
        log.info("Checking if 802.1X plugin is running on RADIUS server")
        status_output = self.exec_cmd("fstool dot1x status")
        if "is running" in status_output:
            log.info("RADIUS server is running")
            return True
        else:
            log.error("RADIUS server is not running")
            return False

    def restart_dot1x_plugin(self, timeout: int = 60, interval: int = 5) -> None:
        log.info("Restarting 802.1X plugin on RADIUS server")
        self.exec_cmd("fstool dot1x restart")
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.dot1x_plugin_running():
                log.info("802.1X plugin restarted successfully and is running")
                return
            log.info(f"Waiting for plugin to start... Retrying in {interval} seconds")
            time.sleep(interval)

        log.error("802.1X plugin failed to restart within the timeout period")



