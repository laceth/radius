import time

from framework.log.logger import log
from lib.plugin.radius.pre_admission_rule import edit_pre_admission_rule, set_pre_admission_rules_remote
from lib.plugin.radius.radius_base import RadiusBase
from lib.plugin.radius.radius_plugin_settings import configure_radius_plugin

DOT1X_RESTART_COMMAND = "fstool dot1x restart"
DOT1X_UPTIME_COMMAND = "fstool dot1x uptime"
DOT1X_RESTART_TIMEOUT = 60
DOT1X_CHECK_INTERVAL = 5
DOT1X_RUNNING_VERIFICATION_STRING = " days"


class Radius(RadiusBase):
    def exec_cmd(self, command: str, timeout: int = 15) -> str:
        return self.platform.exec_command(command, timeout)

    def dot1x_plugin_running(self) -> bool:
        """
        Check if 802.1X plugin is running by verifying uptime output contains ' days'.

        Returns:
            True if plugin is running, False otherwise.
        """
        log.info("Checking if 802.1X plugin is running on RADIUS server")
        try:
            uptime_output = self.exec_cmd(DOT1X_UPTIME_COMMAND)
            log.info(f"Uptime command output: {uptime_output}")
            if DOT1X_RUNNING_VERIFICATION_STRING in uptime_output:
                log.info("RADIUS server is running")
                return True
            else:
                log.warning("RADIUS server is not yet running (uptime not showing days)")
                return False
        except Exception as e:
            log.warning(f"Failed to check plugin status: {e}")
            return False

    def restart_dot1x_plugin(self, timeout: int = DOT1X_RESTART_TIMEOUT, interval: int = DOT1X_CHECK_INTERVAL) -> None:
        """
        Restart the 802.1X plugin and wait until it's running.

        Verification is done by checking 'fstool dot1x uptime' output for ' days' string,
        which indicates the plugin is fully operational.

        Args:
            timeout: Maximum time in seconds to wait for the plugin to start (default: 60).
            interval: Time in seconds between status checks (default: 5).

        Raises:
            Exception: If the plugin fails to start within the timeout period.
        """
        log.info("Restarting 802.1X plugin on RADIUS server")
        try:
            self.exec_cmd(DOT1X_RESTART_COMMAND)
            start_time = time.time()
            while time.time() - start_time < timeout:
                if self.dot1x_plugin_running():
                    log.info("802.1X plugin restarted successfully and is running")
                    return
                log.info(f"Waiting for plugin to start... Retrying in {interval} second(s)")
                time.sleep(interval)
            raise Exception(f"802.1X plugin is not running after {timeout} seconds")
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
            if isinstance(rules, list) and rules and isinstance(rules[0], dict) and "auth" in rules[0]:
                set_pre_admission_rules_remote(rules, self.platform)
                self.restart_dot1x_plugin()
                return

            edit_pre_admission_rule(rules, self.platform, condition_slot=condition_slot)
            self.restart_dot1x_plugin() # run after setting rules
        except Exception as e:
            raise Exception(f"Failed to set pre-admission rules: {e}")

    def plugin_setting(self, conf_dict):
        """
            Configure RADIUS plugin settings based on the provided configuration dictionary.
            ie. conf_dict = {
            "active directory port for ldap queries": "global catalog",
            "enable radsec": "true",
            "allow only radsec connections": "False",
            "counteract radius radsec port": 12345
        }
        """
        try:
            log.info("Configuring RADIUS plugin settings")
            configure_radius_plugin(conf_dict, self.platform)
            self.restart_dot1x_plugin()
        except Exception as e:
            raise Exception(f"Failed to configure RADIUS plugin settings: {e}")
