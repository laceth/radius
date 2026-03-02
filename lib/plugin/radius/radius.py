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
DOT1X_REQUIRED_PROCESSES = ("radiusd", "winbindd", "redis-server")

DEFAULT_LOCAL_PROPERTY_FILE_PATH = "/usr/local/forescout/plugin/dot1x/local.properties"
AUTH_SOURCE_NULL_KEY = "config.auth_source_null.value"
AUTH_SOURCE_DEFAULT_KEY = "config.auth_source_default.value"


class Radius(RadiusBase):
    def __init__(self, platform, version="1.0.0", username=None, password=None):
        super().__init__(platform, version=version, username=username, password=password)
        self.has_change = False

    def exec_cmd(self, command: str, timeout: int = 15, log_output: bool = False, log_command: bool = False) -> str:
        return self.platform.exec_command(command, timeout, log_output=log_output, log_command=log_command)

    def _get_process_uptime_seconds(self, status_output: str, process_name: str) -> int:
        """
        Extract a sub-process uptime in seconds from 'fstool dot1x status' output.

        Looks for a line like:
            radiusd (pid 28055) is running for 00:54.
            winbindd (pid 27705) of txqalab is running for 01:01.

        Supported time formats: 'MM:SS', 'HH:MM:SS', 'DAYS-HH:MM:SS'.

        Args:
            status_output: Full output of 'fstool dot1x status'.
            process_name: Process to look for (e.g. 'radiusd', 'winbindd', 'redis-server').

        Returns:
            Uptime in seconds, or -1 if the process line is not found or not parseable.
        """
        for line in status_output.splitlines():
            if process_name in line.lower() and 'is running for' in line:
                m = re.search(r'is running for\s+(.+)', line)
                if not m:
                    continue

                time_str = m.group(1).strip().rstrip('.')

                # DAYS-HH:MM:SS
                p = re.match(r'^(\d+)-(\d{2}):(\d{2}):(\d{2})$', time_str)
                if p:
                    return int(p.group(1)) * 86400 + int(p.group(2)) * 3600 + int(p.group(3)) * 60 + int(p.group(4))

                # HH:MM:SS
                p = re.match(r'^(\d{2,}):(\d{2}):(\d{2})$', time_str)
                if p:
                    return int(p.group(1)) * 3600 + int(p.group(2)) * 60 + int(p.group(3))

                # MM:SS
                p = re.match(r'^(\d{2,}):(\d{2})$', time_str)
                if p:
                    return int(p.group(1)) * 60 + int(p.group(2))

                return -1
        return -1

    def dot1x_plugin_running(self) -> bool:
        """
        Check if the 802.1X plugin is ready by verifying that **all** required
        sub-processes (radiusd, winbindd, redis-server) are running and that
        radiusd has been up for at least DOT1X_MIN_RADIUSD_UPTIME_SECONDS.

        Uses 'fstool dot1x status' which reports the uptime of each sub-process.
        The radiusd uptime threshold guards against the plugin restarting several
        times in the first seconds after a restart command.

        Returns:
            True if all sub-processes are running and radiusd uptime ≥ threshold,
            False otherwise.
        """
        try:
            status_output = self.exec_cmd(DOT1X_STATUS_COMMAND)
            log.debug(f"dot1x status output:\n{status_output}")

            # Collect uptime for every required sub-process
            uptimes = {}
            not_running = []
            for proc in DOT1X_REQUIRED_PROCESSES:
                uptime = self._get_process_uptime_seconds(status_output, proc)
                if uptime < 0:
                    not_running.append(proc)
                else:
                    uptimes[proc] = uptime

            # Build a single summary line
            parts = [f"{p}={uptimes[p]}s" for p in DOT1X_REQUIRED_PROCESSES if p in uptimes]
            if not_running:
                parts += [f"{p}=DOWN" for p in not_running]
            summary = ", ".join(parts)

            if not_running:
                log.info(f"dot1x status: {summary} — waiting for: {', '.join(not_running)}")
                return False

            radiusd_seconds = uptimes["radiusd"]
            if radiusd_seconds >= DOT1X_MIN_RADIUSD_UPTIME_SECONDS:
                log.info(f"dot1x status: {summary} — plugin is ready")
                return True
            else:
                log.info(f"dot1x status: {summary} — radiusd not yet stable (need {DOT1X_MIN_RADIUSD_UPTIME_SECONDS}s)")
                return False
        except Exception as e:
            log.warning(f"Failed to check plugin status: {e}")
            return False

    def restart_dot1x_plugin(self) -> None:
        """
        Restart the 802.1X plugin and wait for 'Done starting RADIUS.' confirmation.

        The command blocks until the plugin outputs its full stop/start sequence.
        After confirmation, sleeps for 5 seconds to allow sub-processes to stabilise.

        Does **not** poll sub-process readiness.  Call ``wait_until_running()``
        afterwards when the plugin must be fully operational before the next step.
        """
        log.info(f"Restarting 802.1X plugin on {self.platform.ipaddress}")
        output = self.exec_cmd(DOT1X_RESTART_COMMAND, timeout=120)
        if "Done starting RADIUS." in output:
            log.info("Received 'Done starting RADIUS.' confirmation")
        else:
            log.warning(f"'Done starting RADIUS.' not found in restart output:\n{output}")
        log.info("Sleeping 5 seconds for sub-processes to stabilise")
        time.sleep(5)

    def wait_until_running(self, timeout: int = DOT1X_RESTART_TIMEOUT, interval: int = DOT1X_CHECK_INTERVAL) -> None:
        """
        Poll 'fstool dot1x status' until all sub-processes are stable.

        Waits until radiusd, winbindd, and redis-server are all running
        and radiusd uptime reaches ``DOT1X_MIN_RADIUSD_UPTIME_SECONDS``.

        Args:
            timeout: Maximum wait in seconds (default: 300).
            interval: Seconds between polls (default: 10).

        Raises:
            Exception: If the plugin is not ready within *timeout* seconds.
        """
        log.info(f"Waiting for 802.1X plugin to become ready on {self.platform.ipaddress} (timeout={timeout}s)")
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.dot1x_plugin_running():
                log.info("802.1X plugin is ready")
                return
            log.info(f"Waiting for plugin to start... Retrying in {interval} second(s)")
            time.sleep(interval)
        raise Exception(f"802.1X plugin is not running after {timeout} seconds")

    def apply_dot1x_changes(self) -> None:
        """Restart dot1x if has_change is set, otherwise skip."""
        if self.has_change:
            log.info("Restarting dot1x plugin to apply pending changes...")
            self.restart_dot1x_plugin()
            self.has_change = False
        else:
            log.info("Dot1x has no changes, skipping restart")

    def set_pre_admission_rules(self, rules: list, condition_slot: int = 1) -> None:
        """
        Set pre-admission rules on the RADIUS server by editing local.properties.
        Then restart the dot1x plugin if there are changes.
        Args:
            rules (list): List of pre-admission rules to set.
            condition_slot (int): Which config.defpol_cond{slot}.value to edit.
            Use 1 for Priority 1 rule, 2 for Priority 2, etc.
        """
        log.info(f"Setting pre-admission rules: {len(rules)} rule(s)")

        try:
            if isinstance(rules, list) and rules and isinstance(rules[0], dict) and "auth" in rules[0]:
                log.info("Using multi-rule format with auth values")
                if set_pre_admission_rules_remote(rules, self.platform):
                    self.has_change = True
                    log.info(f"Pre-admission rules have changes, set self.has_change = {self.has_change}")
            else:
                log.info(f"Using single condition format for slot {condition_slot}")
                if edit_pre_admission_rule(rules, self.platform, condition_slot=condition_slot):
                    self.has_change = True
                    log.info(f"Pre-admission rules have changes, set self.has_change = {self.has_change}")
        except Exception as e:
            raise Exception(f"Failed to set pre-admission rules: {e}")
        self.apply_dot1x_changes()

    def configure_radius_plugin(self, conf_dict):
        """
        Configure RADIUS plugin settings based on the provided configuration dictionary.
        Automatically restarts the dot1x plugin after configuration has changed.

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

        # Preload all properties in one SFTP read to avoid a separate connection per property
        current_props = {}
        try:
            current_props = self._get_property(DEFAULT_LOCAL_PROPERTY_FILE_PATH)
        except Exception as e:
            log.debug(f"Failed to preload dot1x properties: {e}")

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
                new_value = str(val).lower()
                current_value = current_props.get(prop_key)
                if current_value is not None and current_value.lower() == new_value:
                    log.info(f"{prop_key} already set to '{current_value}', skipping")
                    continue

                cmd = "fstool dot1x set_property %s %s" % (prop_key, new_value)
                cmd_list.append(cmd)
                self.exec_cmd(cmd, log_command=True)
                if not self.has_change:
                    self.has_change = True

        except Exception as e:
            log.error(f"Error configuring RADIUS plugin settings on {self.platform.ipaddress}: {e}")
            raise e
        self.apply_dot1x_changes()
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
        else:
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
                self.has_change = True
                log.info(f"Domain join has changes, set self.has_change = {self.has_change}")

            except Exception as e:
                raise Exception(f"Failed to join domain '{domain_name}': {e}")
        self.apply_dot1x_changes()

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
            output = self.exec_cmd(cmd, log_command=True, timeout=timeout)
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
            current_value = self._get_property(file_path, AUTH_SOURCE_NULL_KEY)
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
            return self._get_property(file_path, AUTH_SOURCE_DEFAULT_KEY)
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

    def _get_property(self, file_path: str = DEFAULT_LOCAL_PROPERTY_FILE_PATH, key: str = None) -> "str | dict":
        """Read property value(s) from local.properties via a single SFTP connection.

        Args:
            file_path: Remote path to local.properties.
            key: Property key to look up, or None to return all key-value pairs as a dict.

        Returns:
            str: The value for the given key.
            dict: All key-value pairs when key is None.
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.platform.ipaddress, username=self.platform.username, password=self.platform.password)

        sftp = None
        try:
            sftp = ssh.open_sftp()

            with sftp.open(file_path, "r") as f:
                lines = f.readlines()

            if key is None:
                props = {}
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^([A-Za-z0-9_.]+)\s*=\s*(.*)$", line)
                    if m:
                        props[m.group(1)] = m.group(2)
                return props

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