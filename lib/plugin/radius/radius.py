import time

from framework.log.logger import log
from lib.plugin.radius.pre_admission_rule import edit_pre_admission_rule, set_pre_admission_rules_remote
from lib.plugin.radius.radius_base import RadiusBase
from lib.plugin.radius.radius_plugin_settings import radius_setting_option_mapping, implicit_field_mapping
import paramiko
from contextlib import suppress

import re

DOT1X_RESTART_COMMAND = "fstool dot1x restart"
DOT1X_STATUS_COMMAND = "fstool dot1x status"
DOT1X_RESTART_TIMEOUT = 300
DOT1X_CHECK_INTERVAL = 10
DOT1X_MIN_RADIUSD_UPTIME_SECONDS = 45

DEFAULT_LOCAL_PROPERTY_FILE_PATH = "/usr/local/forescout/plugin/dot1x/local.properties"
AUTH_SOURCE_NULL_KEY = "config.auth_source_null.value"
AUTH_SOURCE_DEFAULT_KEY = "config.auth_source_default.value"


class Radius(RadiusBase):
    def exec_cmd(self, command: str, timeout: int = 15) -> str:
        return self.platform.exec_command(command, timeout)

    @staticmethod
    def _parse_running_time(time_str: str) -> int:
        """
        Parse a running-time string from 'fstool dot1x status' into total seconds.

        Supported formats:
            'MM:SS'                  →  e.g. '00:54'
            'HH:MM:SS'              →  e.g. '01:02:03'
            'DAYS-HH:MM:SS'         →  e.g. '145-19:21:22'

        Returns:
            Total seconds, or -1 if parsing fails.
        """
        time_str = time_str.strip().rstrip('.')

        # DAYS-HH:MM:SS
        m = re.match(r'^(\d+)-(\d{2}):(\d{2}):(\d{2})$', time_str)
        if m:
            return int(m.group(1)) * 86400 + int(m.group(2)) * 3600 + int(m.group(3)) * 60 + int(m.group(4))

        # HH:MM:SS
        m = re.match(r'^(\d{2,}):(\d{2}):(\d{2})$', time_str)
        if m:
            return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))

        # MM:SS
        m = re.match(r'^(\d{2,}):(\d{2})$', time_str)
        if m:
            return int(m.group(1)) * 60 + int(m.group(2))

        return -1

    def _get_radiusd_uptime_seconds(self, status_output: str) -> int:
        """
        Extract radiusd uptime in seconds from 'fstool dot1x status' output.

        Looks for a line like:
            radiusd (pid 28055) is running for 00:54.

        Returns:
            Uptime in seconds, or -1 if radiusd line not found or not parseable.
        """
        for line in status_output.splitlines():
            if 'radiusd' in line.lower() and 'is running for' in line:
                # Extract the time portion after 'is running for '
                m = re.search(r'is running for\s+(.+)', line)
                if m:
                    return self._parse_running_time(m.group(1))
        return -1

    def dot1x_plugin_running(self) -> bool:
        """
        Check if the 802.1X plugin is ready by verifying that radiusd has been
        running for at least DOT1X_MIN_RADIUSD_UPTIME_SECONDS (45 s).

        Uses 'fstool dot1x status' which reports the uptime of each sub-process
        (radiusd, winbindd, redis-server).  The radiusd uptime is the one that
        matters — the plugin restarts several times in the first seconds after
        a restart command, so a stable radiusd uptime ≥ 45 s means it is truly
        ready.

        Returns:
            True if radiusd uptime ≥ threshold, False otherwise.
        """
        log.info("Checking if 802.1X plugin is running on RADIUS server")
        try:
            status_output = self.exec_cmd(DOT1X_STATUS_COMMAND)
            log.info(f"dot1x status output:\n{status_output}")

            radiusd_seconds = self._get_radiusd_uptime_seconds(status_output)

            if radiusd_seconds >= DOT1X_MIN_RADIUSD_UPTIME_SECONDS:
                log.info(f"radiusd is running (uptime: {radiusd_seconds}s)")
                return True
            elif radiusd_seconds >= 0:
                log.warning(
                    f"radiusd uptime is {radiusd_seconds}s, waiting for {DOT1X_MIN_RADIUSD_UPTIME_SECONDS}s"
                )
                return False
            else:
                log.warning(f"radiusd is not yet running or not found in status output")
                return False
        except Exception as e:
            log.warning(f"Failed to check plugin status: {e}")
            return False

    def restart_dot1x_plugin(self, timeout: int = DOT1X_RESTART_TIMEOUT, interval: int = DOT1X_CHECK_INTERVAL) -> None:
        """
        Restart the 802.1X plugin and wait until radiusd is stable.

        Verification uses 'fstool dot1x status' and waits until radiusd uptime
        reaches DOT1X_MIN_RADIUSD_UPTIME_SECONDS (45 s).

        Args:
            timeout: Maximum time in seconds to wait for the plugin to start (default: 500).
            interval: Time in seconds between status checks (default: 10).

        Raises:
            Exception: If the plugin fails to start within the timeout period.
        """
        log.info(f"Restarting 802.1X plugin on RADIUS server on {self.platform.ipaddress}")
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
        log.info(f"Configuring RADIUS plugin settings on {self.platform.ipaddress}")
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
            log.error(f"Error configuring RADIUS plugin settings on {self.platform.ipaddress}: {e}")
            raise e
        log.info(f"RADIUS plugin settings configured successfully on {self.platform.ipaddress}")
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
        if self.test_join_domain(domain_name, timeout):
            log.info(f"Domain '{domain_name}' is already joined, skipping join operation")
            return

        # Domain not joined, proceed with join
        cmd = f"fstool dot1x join {domain_name} {ad_username} {ad_password}"

        log.info(f"Joining domain '{domain_name}' for Radius plugin")
        try:
            output = self.exec_cmd(cmd, timeout=timeout)
            log.info(f"Domain join command output: {output}")

            # Check for success indicator
            if "Result: SUCCESS" not in output:
                raise Exception(f"Domain join failed: {output}")

            log.info(f"Successfully joined domain '{domain_name}'")

            # Restart plugin to apply changes
            self.restart_dot1x_plugin()

        except Exception as e:
            raise Exception(f"Failed to join domain '{domain_name}': {e}")

    def test_join_domain(self, domain_name: str, timeout: int = 60) -> bool:
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
            dot1x.test_join_domain("txqalab-dc1")
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
                log.debug(f"Domain '{domain_name}' is already joined")
                return True

            log.info(f"Domain '{domain_name}' is not joined: {output}")
            return False

        except Exception as e:
            raise Exception(f"Failed to test join domain '{domain_name}': {e}")

    def set_null(self, auth_source: str, file_path: str = DEFAULT_LOCAL_PROPERTY_FILE_PATH) -> None:
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

    def set_default(self, auth_source: str, file_path: str = DEFAULT_LOCAL_PROPERTY_FILE_PATH) -> None:
        """Set config.auth_source_default.value to specified auth_source (checks current value first)."""
        try:
            current_value = self.get_default_auth_source(file_path)
            if current_value == auth_source:
                log.info(f"Auth source default already set to '{auth_source}', skipping")
                return

            log.info(f"Setting auth_source {auth_source} to Default (current: '{current_value}')")
            self._update_property(AUTH_SOURCE_DEFAULT_KEY, auth_source, file_path)
        except Exception as e:
            raise Exception(f"Failed to set auth source default to '{auth_source}': {e}")

    def get_default_auth_source(self, file_path: str = DEFAULT_LOCAL_PROPERTY_FILE_PATH) -> str:
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