from framework.log.logger import log
from lib.plugin.radius.pre_admission_rule import edit_pre_admission_rule, set_pre_admission_rules_remote
from lib.plugin.radius.radius_base import RadiusBase
from lib.plugin.radius.radius_plugin_settings import configure_radius_plugin, restart_dot1x_plugin


class Radius(RadiusBase):
    def exec_cmd(self, command: str, timeout: int = 15) -> str:
        return self.platform.exec_command(command, timeout)

    # Support condition_slot
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
                restart_dot1x_plugin(self.platform)
                return

            edit_pre_admission_rule(rules, self.platform, condition_slot=condition_slot)
            restart_dot1x_plugin(self.platform)
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
        except Exception as e:
            raise Exception(f"Failed to configure RADIUS plugin settings: {e}")
