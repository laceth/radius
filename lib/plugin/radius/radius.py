import time

from framework.log.logger import log
from lib.plugin.radius.pre_admission_rule import edit_pre_admission_rule
from lib.plugin.radius.radius_base import RadiusBase
from lib.plugin.radius.radius_plugin_settings import configure_radius_plugin

DOT1X_RESTART_COMMAND = "fstool dot1x restart"
DOT1X_RESTART_TIMEOUT = 60
DO1X_CHECK_INTERVAL = 5


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

    def restart_dot1x_plugin(self, timeout: int = DOT1X_RESTART_TIMEOUT, interval: int = DO1X_CHECK_INTERVAL) -> None:
        log.info("Restarting 802.1X plugin on RADIUS server")
        try:
            self.exec_cmd(DOT1X_RESTART_COMMAND)
            start_time = time.time()
            while time.time() - start_time < timeout:
                if self.dot1x_plugin_running():
                    log.info("802.1X plugin restarted successfully and is running")
                    return
                log.info(f"Waiting for plugin to start... Retrying in {interval} seconds")
                time.sleep(interval)
        except Exception as e:
            raise Exception(f"Failed to restart 802.1X plugin: {e}")

    def set_pre_admission_rules(self, rules: list, condition_slot: int = 1) -> None:
        """
        Set pre-admission rules on the RADIUS server by editing local.properties,
        then restart the dot1x plugin for multiple rules in local.properties.

        Args:
            rules (list): List of pre-admission rules to set.
            condition_slot (int): Which config.defpol_cond{slot}.value to edit.
                                 Use 1 for Priority 1 rule, 2 for Priority 2, etc.
        """
        try:
            edit_pre_admission_rule(rules, self.platform, condition_slot=condition_slot)
            self.restart_dot1x_plugin()
        except Exception as e:
            raise Exception(f"Failed to set pre-admission rules: {e}")

    def plugin_setting(self, conf_dict):
        """Configure RADIUS plugin settings based on the provided configuration dictionary."""
        try:
            log.info("Configuring RADIUS plugin settings")
            configure_radius_plugin(conf_dict, self.platform)
            self.restart_dot1x_plugin()
        except Exception as e:
            raise Exception(f"Failed to configure RADIUS plugin settings: {e}")
