import time
from framework.log.logger import log

# Commands
DOT1X_PLUGIN_RESTART_CMD = "fstool dot1x restart"
DOT1X_PLUGIN_STATUS_CMD = "fstool dot1x status"

# Default
DEFAULT_RADIUS_RESTART_TIMEOUT = 60
DEFAULT_POLL_INTERVAL = 5

class Radius:
    version = "1.0.0"
    platform = None

    def __init__(self, platform, version="1.0.0"):
        self.platform = platform
        self.version = version

    def exec_cmd(self, command: str, timeout: int = 15) -> str:
        return self.platform.exec_command(command, timeout)

    def plugin_running(self) -> bool:
        log.info("Checking if 802.1X plugin is running on RADIUS server")
        status_output = self.exec_cmd(DOT1X_PLUGIN_STATUS_CMD)
        if "is running" in status_output:
            log.info("RADIUS server is running")
            return True
        else:
            log.error("RADIUS server is not running")
            return False


    def restart_dot1x_plugin(self, timeout: int = DEFAULT_RADIUS_RESTART_TIMEOUT, interval: int = DEFAULT_POLL_INTERVAL) -> None:
        log.info("Restarting 802.1X plugin on RADIUS server")
        self.exec_cmd(DOT1X_PLUGIN_RESTART_CMD)
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.plugin_running():
                log.info("802.1X plugin restarted successfully and is running")
                return
            log.info(f"Waiting for plugin to start... Retrying in {interval} seconds")
            time.sleep(interval)

        log.error("802.1X plugin failed to restart within the timeout period")

    def set_radius_pre_admission_rule(self, rule: str) -> None:
        log.info(f"Setting RADIUS pre-admission rule: {rule}")

