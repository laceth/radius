import time

from framework.log.logger import log
from lib.plugin.radius.pre_admission_rule import edit_pre_admission_rule, set_pre_admission_rules_remote
from lib.plugin.radius.radius_base import RadiusBase
from lib.plugin.radius.radius_plugin_settings import radius_setting_option_mapping, implicit_field_mapping
import paramiko
from contextlib import suppress

DOT1X_RESTART_COMMAND = "fstool dot1x restart"
DOT1X_UPTIME_COMMAND = "fstool dot1x uptime"
DOT1X_RESTART_TIMEOUT = 300
DOT1X_CHECK_INTERVAL = 5
DOT1X_RUNNING_VERIFICATION_STRING = " days"
DEFAULT_LOCAL_PROPERTY_FILE_PATH = "/usr/local/forescout/plugin/dot1x/local.properties"
AUTH_SOURCE_NULL_KEY = "config.auth_source_null.value"
AUTH_SOURCE_DEFAULT_KEY = "config.auth_source_default.value"


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
            timeout: Maximum time in seconds to wait for the plugin to start (default: 300).
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
        log.info(f"Setting pre-admission rules: {len(rules)} rule(s)")


        try:
            if isinstance(rules, list) and rules and isinstance(rules[0], dict) and "auth" in rules[0]:
                log.info("Using multi-rule format with auth values")
                set_pre_admission_rules_remote(rules, self.platform)
                self.restart_dot1x_plugin()
                return

            log.info(f"Using single condition format for slot {condition_slot}")
            edit_pre_admission_rule(rules, self.platform, condition_slot=condition_slot)
            self.restart_dot1x_plugin()
        except Exception as e:
            raise Exception(f"Failed to set pre-admission rules: {e}")

    def configure_radius_plugin(self, conf_dict):
        """
        Configure RADIUS plugin settings based on the provided configuration dictionary.
        Automatically restarts the dot1x plugin after configuration.

        Args:
            conf_dict: Dictionary of configuration options.

        Example:
            conf_dict = {
                "active directory port for ldap queries": "global catalog",
                "enable radsec": "true",
                "allow only radsec connections": "False",
                "counteract radius radsec port": 12345
            }
        """
        cmd_list = []
        log.info("Configuring RADIUS plugin settings")
        try:
            for key, val in conf_dict.items():
                # Skip empty/None values
                if val is None or str(val).strip() == "":
                    log.info(f"Skipping empty value for: {key}")
                    continue

                if key.lower() not in radius_setting_option_mapping:
                    valid_options = ', '.join(radius_setting_option_mapping.keys())
                    raise Exception("Invalid configuration option: %s. Valid options are: %s" % (key, valid_options))
                prop_key = radius_setting_option_mapping[key.lower()]
                if prop_key.lower() in implicit_field_mapping:
                    if str(val).lower() not in implicit_field_mapping[prop_key.lower()]:
                        raise Exception("%s doesn't have a option for %s" % (prop_key, val))
                    val = implicit_field_mapping[prop_key.lower()][str(val).lower()]
                cmd = "fstool dot1x set_property %s %s" % (prop_key, str(val).lower())
                cmd_list.append(cmd)
                self.platform.exec_command(cmd)

            self.restart_dot1x_plugin()

        except Exception as e:
            log.error(f"Error configuring RADIUS plugin settings: {e}")
            raise e
        log.info("RADIUS plugin settings configured successfully")
        return cmd_list

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
            self.configure_radius_plugin(conf_dict)
        except Exception as e:
            raise Exception(f"Failed to configure RADIUS plugin settings: {e}")

    def join_domain(self, domain_name: str, ad_username: str, ad_password: str, timeout: int = 60) -> None:
        """
        Join a domain in User Directory using fstool dot1x join command.

        First checks if the domain is already joined using test_domain_join.
        If already joined, skips the join operation. Otherwise, joins the domain.

        This adds the domain to the RADIUS plugin configuration for LDAP queries
        and authentication against Active Directory.

        Args:
            domain_name: Domain name (e.g., "txqalab-dc1", "mycompany-dc2")
            ad_username: Active Directory username (e.g., "administrator")
            ad_password: Active Directory password (e.g., "aristo")
            timeout: Command timeout in seconds (default: 60)

        Example:
            dot1x.join_domain("txqalab-dc1", "administrator", "aristo")
            # Executes: fstool dot1x join txqalab-dc1 administrator aristo

        Raises:
            Exception: If the join command fails
        """
        log.info(f"Configuring RADIUS Authentication Source with domain '{domain_name}'")
        # Check if domain is already joined
        try:
            if self.test_domain_join(domain_name, timeout):
                log.info(f"Domain '{domain_name}' is already joined, skipping join operation")
                return
        except Exception as e:
            log.info(f"Domain '{domain_name}' is not joined yet, proceeding with join: {e}")
        
        # Domain not joined, proceed with join
        cmd = f"fstool dot1x join {domain_name} {ad_username} {ad_password}"

        log.info(f"Joining domain '{domain_name}' for Radius plugin")
        try:
            output = self.exec_cmd(cmd, timeout=timeout)
            log.info(f"Domain join command output: {output}")

            # Check for success indicators
            if "error" in output.lower() or "failed" in output.lower():
                raise Exception(f"Domain join failed: {output}")

            log.info(f"Successfully joined domain '{domain_name}'")

            # Restart plugin to apply changes
            self.restart_dot1x_plugin()

        except Exception as e:
            raise Exception(f"Failed to add domain '{domain_name}': {e}")

    def test_domain_join(self, domain_name: str, timeout: int = 60) -> bool:
        """
        Test domain join without actually joining using fstool dot1x testjoin command.

        This verifies the domain configuration and credentials are correct
        without modifying the RADIUS plugin configuration.

        Args:
            domain_name: Domain name to test (e.g., "txqalab-dc1", "mycompany-dc2")
            timeout: Command timeout in seconds (default: 60)

        Returns:
            True if test join is successful

        Example:
            dot1x.test_domain_join("txqalab-dc1")
            # Executes: fstool dot1x testjoin txqalab-dc1
            # Expected output: Join OK [txqalab-dc1]

        Raises:
            Exception: If the test join command fails
        """
        cmd = f"fstool dot1x testjoin {domain_name}"

        log.info(f"Testing domain '{domain_name}' joined status with testjoin command")
        try:
            output = self.exec_cmd(cmd, timeout=timeout)
            log.info(f"Test join command output: {output}")

            # Check for success indicator
            if "Join OK" in output and domain_name in output:
                log.info(f"Domain '{domain_name}' is already joined")
                return True
            else:
                raise Exception(f"Domain '{domain_name}' is not joined: {output}")

        except Exception as e:
            raise Exception(f"Failed to test join domain '{domain_name}': {e}")

    def get_ad_config_from_dict(self, ad_config: dict, domain_key: str = 'ad1') -> dict:
        """
        Read Active Directory domain configuration from configuration dictionary.

        Args:
            ad_config: Dictionary containing AD configuration (e.g., from YAML)
            domain_key: Key to read from ad_config (default: 'ad1')

        Returns:
            Dictionary with 'ad_name', 'ad_ud_user', 'ad_secret' keys, or empty dict if not found

        Example:
            ad_config = {
                'ad1': {
                    'ad_name': 'txqalab-dc1',
                    'ad_ud_user': 'administrator',
                    'ad_secret': 'aristo'
                }
            }
            config = dot1x.get_ad_config_from_dict(ad_config)
            # Returns: {'ad_name': 'txqalab-dc1', 'ad_ud_user': 'administrator', 'ad_secret': 'aristo'}
        """
        try:
            if domain_key not in ad_config:
                log.info(f"No '{domain_key}' configuration found in ad_config")
                return {}

            domain_config = ad_config[domain_key]
            ad_name = domain_config.get('ad_name')
            
            if not ad_name:
                log.warning(f"No 'ad_name' specified in {domain_key} config")
                return {}

            username = domain_config.get('ad_ud_user', 'administrator')
            password = domain_config.get('ad_secret', 'aristo')

            return {
                'ad_name': ad_name,
                'ad_ud_user': username,
                'ad_secret': password
            }
        except Exception as e:
            raise Exception(f"Failed to get AD config from dict (domain_key='{domain_key}'): {e}")

    def set_auth_source_null(self, auth_source: str, file_path: str = DEFAULT_LOCAL_PROPERTY_FILE_PATH) -> None:
        """Set config.auth_source_null.value to specified auth_source (checks current value first)."""
        try:
            current_value = self._get_property(AUTH_SOURCE_NULL_KEY, file_path)
            if current_value == auth_source:
                log.info(f"Auth source null already set to '{auth_source}', skipping")
                return
            
            log.info(f"Setting auth_source {auth_source} to Null (current: '{current_value}')")
            self._update_property(AUTH_SOURCE_NULL_KEY, auth_source, file_path)
        except Exception as e:
            raise Exception(f"Failed to set auth source null to '{auth_source}': {e}")

    def set_auth_source_default(self, auth_source: str, file_path: str = DEFAULT_LOCAL_PROPERTY_FILE_PATH) -> None:
        """Set config.auth_source_default.value to specified auth_source (checks current value first)."""
        try:
            current_value = self.get_auth_source_default(file_path)
            if current_value == auth_source:
                log.info(f"Auth source default already set to '{auth_source}', skipping")
                return
            
            log.info(f"Setting auth_source {auth_source} to Default (current: '{current_value}')")
            self._update_property(AUTH_SOURCE_DEFAULT_KEY, auth_source, file_path)
        except Exception as e:
            raise Exception(f"Failed to set auth source default to '{auth_source}': {e}")

    def get_auth_source_default(self, file_path: str = DEFAULT_LOCAL_PROPERTY_FILE_PATH) -> str:
        """Get current value of config.auth_source_default.value."""
        try:
            return self._get_property(AUTH_SOURCE_DEFAULT_KEY, file_path)
        except Exception as e:
            raise Exception(f"Failed to get auth source default: {e}")

    def _update_property(self, key: str, value: str, file_path: str) -> None:
        """Update a single property in local.properties."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.platform.ipaddress, username=self.platform.username, password=self.platform.password)

        sftp = None
        try:
            sftp = ssh.open_sftp()

            # Read existing file
            with sftp.open(file_path, "r") as f:
                lines = f.readlines()

            # Find and update the key, or append if not found
            updated = False
            for i, line in enumerate(lines):
                if line.startswith(f"{key}="):
                    lines[i] = f"{key}={value}\n"
                    updated = True
                    break

            if not updated:
                lines.append(f"{key}={value}\n")

            # Write back
            with sftp.open(file_path, "w") as f:
                f.writelines(lines)

            log.info(f"Updated property: {key}={value}")

        finally:
            with suppress(Exception):
                if sftp:
                    sftp.close()
            with suppress(Exception):
                ssh.close()

    def _get_property(self, key: str, file_path: str) -> str:
        """Read a single property value from local.properties."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.platform.ipaddress, username=self.platform.username, password=self.platform.password)

        sftp = None
        try:
            sftp = ssh.open_sftp()

            with sftp.open(file_path, "r") as f:
                lines = f.readlines()

            for line in lines:
                if line.startswith(f"{key}="):
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        value = parts[1].strip()
                        log.debug(f"Current property: {key}={value}")
                        return value
                    else:
                        log.debug(f"Current property: {key}=")
                        return ""
            return ""

        finally:
            with suppress(Exception):
                if sftp:
                    sftp.close()
            with suppress(Exception):
                ssh.close()