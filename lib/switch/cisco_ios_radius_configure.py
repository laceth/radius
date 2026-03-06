import ipaddress
import re
from enum import Enum
from typing import Dict, List, Optional

from framework.log.logger import log
from lib.switch.action import Action
from lib.switch.cisco_ios import CiscoIOS
from lib.switch.radius_configure_base import RadiusConfigureBase


class RadiusCmd(str, Enum):
    # SHOW commands
    SHOW_INTERFACE = "show run | section ^interface {port}$"
    SHOW_AAA = "show running-config | include ^aaa (authentication|authorization|accounting)"
    SHOW_DOT1X = "show running-config | inc dot1x"
    SHOW_RADIUS_GROUP = "show running-config | section aaa group server radius {group}"
    SHOW_RADIUS_SERVER = "show running-config | section radius server {name}"
    SHOW_RADIUS_SERVER_ALL = "show running-config | section ^radius server"
    SHOW_COA = "show running-config | section aaa server radius dynamic-author"

    # Global dot1x command
    DOT1X_GLOBAL = "dot1x system-auth-control"

    # Radius server configuration commands
    AAA_NEW_MODEL = "aaa new-model"
    RADIUS_SERVER = "radius server {name}"
    RADIUS_ADDRESS = "address {ip_family} {ip} auth-port 1812 acct-port 1813"
    RADIUS_KEY = "key {secret_type} {secret}"
    RADIUS_TIMEOUT = "timeout {timeout}"
    RADIUS_RETRANSMIT = "retransmit {retransmit}"

    # Radius group configuration commands
    RADIUS_GROUP = "aaa group server radius {group}"
    RADIUS_GROUP_SERVER = "server name {server}"
    RADIUS_GROUP_DEADTIME = "deadtime {deadtime}"

    # Radius aaa configuration commands
    AAA_AUTH = "aaa authentication {auth_type} default group {group}"
    AAA_AUTHZ = "aaa authorization network default group {group}"
    AAA_ACCT = "aaa accounting {auth_type} default start-stop group {group}"

    # Radius coa configuration commands
    COA_ENTER = "aaa server radius dynamic-author"
    COA_CLIENT = "client {ip} server-key {secret}"
    COA_CLIENT_NO = "no client {ip}"

    # Radius interface port configuration commands
    INTERFACE_PORT = "interface {port}"
    SW_MODE_ACCESS = "switchport mode access"
    SW_ACCESS_VLAN = "switchport access vlan {vlan}"
    AUTH_PORT_AUTO = "authentication port-control auto"
    AUTH_PERIODIC = "authentication periodic"
    DOT1X_PAE = "dot1x pae authenticator"
    MAB = "mab"

    def render(self, **kwargs) -> str:
        return self.value.format(**kwargs)


class CiscoIosRadiusConfigure(CiscoIOS, RadiusConfigureBase):
    def __init__(self, ip: str, username: str, password: str) -> None:
        super().__init__(ip, username, password)
        self._aaa_group_name = "group-automation"
        self._aaa_auth_type = "dot1x"
        self._radius_server_prefix = "server-automation"
        self._radius_server_name = ""
        self._teardown_commands_on_port: Dict[str, List[str]] = {}
        self._setup_count: int = 0
        self._debug_sample_len = 50
        self._original_vlan: int = 4095
        self._original_mab_state: Dict[str, bool] = {}
        self._original_dot1x_pae_state: Dict[str, bool] = {}
        self._original_radius_aaa: str = ""
        self._original_radius_servers: Dict[str, List[str]] = {}
        self._original_radius_server_name: str = ""
        self._original_radius_server_group: str = ""
        self._original_radius_coa_exist = bool(False)
        self._original_radius_coa_secret: Optional[str] = None

    def setup_radius_config(
        self,
        port: str,
        radius_server_ip: str,
        secret: Optional[str] = None,
        mab: bool = False,
        vlan: Optional[int] = None,
        aaa_auth_type: str = "dot1x",
        deadtime: int = 3,
        timeout: int = 5,
        retransmit: int = 3,
        **kwargs,
    ) -> bool:
        """
        Main method: Configure RADIUS authentication on a specific port.

        This method orchestrates the complete RADIUS configuration:
            1. Configure dot1x system-auth-control (global setting)
            2. Configure RADIUS server or change existing secret
            3. Configure RADIUS group
            4. Configure AAA authentication
            5. Configure dot1x/MAB on the port

        Args:
            port: Switch port (e.g., "gi0/1", "GigabitEthernet0/1")
            radius_server_ip: IP address of the RADIUS server
            secret: Shared secret for RADIUS communication
            mab: If True, use MAB instead of dot1x pae authenticator (default: False)
            vlan: VLAN ID for the port (default: None - keeps existing VLAN)
            aaa_auth_type: Type of AAA authentication (default: "dot1x")
            deadtime: Deadtime for RADIUS group (default: 3 minutes)
            timeout: Timeout for RADIUS server (default: 5 seconds)
            retransmit: Retransmit count for RADIUS server (default: 3)

        Returns:
            bool: True if all configuration steps succeeded
        """
        try:
            # Increment setup invocation counter
            self._setup_count += 1
            self._port = CiscoIOS.normalize_interface(port)
            log.info(f"Starting RADIUS configuration on port {self._port} for Cisco ios switch {self.ip}")
            action = Action.SETUP
            self._aaa_auth_type = aaa_auth_type
            total_steps = 6
            step = 1
            start_log = "Starting RADIUS Configuration steps"

            # Validate secret is provided (factory supplies default if omitted)
            if not secret:
                log.error("Secret is required when setting up RADIUS")
                return False

            # Step 1: Configure dot1x system-auth-control (setup only, no teardown needed)
            log.info(f"{start_log} {step}/{total_steps}: dot1x system-auth-control")
            if not self._configure_dot1x_system_auth_control():
                log.error("Failed to configure dot1x system-auth-control")
                return False

            # Step 2: Configure RADIUS server
            step += 1
            log.info(f"Starting RADIUS Configuration steps {step}/{total_steps}: RADIUS server")
            if not self._radius_server_name:
                self._generate_radius_server_name(radius_server_ip)
            if not self._configure_radius_server(action, radius_server_ip, secret, timeout, retransmit):
                log.error(f"Failed to configure RADIUS server {radius_server_ip}")
                return False

            # Step 3: Configure RADIUS group
            step += 1
            log.info(f"{start_log} {step}/{total_steps}: RADIUS group")
            if not self._configure_radius_group(action, self._aaa_group_name, self._radius_server_name, deadtime):
                log.error(f"Failed to configure RADIUS group {self._aaa_group_name}")
                return False

            # Step 4: Configure AAA authentication
            step += 1
            log.info(f"{start_log} {step}/{total_steps}: AAA authentication")
            if not self._configure_radius_aaa(action, self._aaa_group_name, self._aaa_auth_type):
                log.error(f"Failed to configure AAA authentication {self._aaa_group_name}")
                return False

            # Step 5: Configure RADIUS CoA (dynamic-author) client with server-key
            step += 1
            log.info(f"{start_log} {step}/{total_steps}: RADIUS CoA (dynamic-author) client")
            if not self._configure_radius_coa(action, radius_server_ip, secret):
                log.error("Failed to configure RADIUS dynamic-author (CoA)")
                return False

            # Step 6: Configure dot1x/MAB on the port
            step += 1
            log.info(f"{start_log} {step}/{total_steps}: {'MAB' if mab else 'dot1x'} on port {self._port}")
            if not self._configure_dot1x_on_port(action, self._port, mab, vlan):
                log.error(f"Failed to configure port {self._port}")
                return False

            log.info(f"Successfully setup all RADIUS configuration on Cisco switch {self.ip}")
            return True

        except Exception as e:
            log.error(f"Failed to setup all RADIUS configuration on Cisco switch {self.ip}: {e}")
            return False

    def teardown_radius_config(self, port: str, radius_server_ip: str, **kwargs) -> bool:
        """
        Remove RADIUS authentication configuration.
            1. Restore all original configuration on the port
            2. Remove AAA authentication & Authorization & Accounting
            3. Remove RADIUS group
            4. Remove RADIUS server
            5. Remove RADIUS CoA (dynamic-author) client

        Args:
            port: Switch port (e.g., "gi0/1", "GigabitEthernet0/1")
            radius_server_ip: IP address of the RADIUS server

        Returns:
            bool: True if all teardown steps succeeded
        """
        try:
            total_steps = 5
            step = 1
            teardown_log = "Starting RADIUS teardown steps"
            self._port = CiscoIOS.normalize_interface(port)
            log.info(f"Starting RADIUS teardown on port {self._port} for Cisco ios switch {self.ip}")

            if not self._radius_server_name:
                self._generate_radius_server_name(radius_server_ip)
            # Step 1: Remove dot1x from the port
            log.info(f"{teardown_log} {step}/{total_steps}: dot1x on port {self._port}")
            if not self._configure_dot1x_on_port(Action.TEARDOWN, self._port, **kwargs):
                log.error(f"Failed to remove dot1x from port {self._port}")
                return False

            # Step 2: Remove RADIUS CoA (dynamic-author) client
            step += 1

            if not self._configure_radius_coa(Action.TEARDOWN, radius_server_ip):
                log.error("Failed to remove RADIUS dynamic-author client")
                return False

            # Step 3: Remove AAA authentication
            step += 1
            log.info(f"{teardown_log} {step}/{total_steps}: AAA authentication")
            if not self._configure_radius_aaa(Action.TEARDOWN, self._aaa_group_name, self._aaa_auth_type):
                log.error("Failed to remove AAA authentication")
                return False

            # Step 4: Remove RADIUS group
            step += 1
            log.info(f"{teardown_log} {step}/{total_steps}: RADIUS group")
            if not self._configure_radius_group(Action.TEARDOWN, self._aaa_group_name, self._radius_server_name):
                log.error(f"Failed to remove RADIUS group {self._aaa_group_name}")
                return False

            # Step 5: Remove RADIUS server
            step += 1
            log.info(f"{teardown_log} {step}/{total_steps}: RADIUS server")
            if not self._configure_radius_server(Action.TEARDOWN, radius_server_ip):
                log.error(f"Failed to remove RADIUS server {radius_server_ip}")
                return False

            log.info(f"Successfully teardown all RADIUS configuration on Cisco switch {self.ip}")
            self._setup_count -= 1
            return True

        except Exception as e:
            log.error(f"Failed to teardown RADIUS configuration on Cisco switch {self.ip}: {e}")
            return False

    def _validate_action(self, action: Action) -> None:
        """Validate that action is either 'setup' or 'teardown'."""
        if action not in [Action.SETUP, Action.TEARDOWN]:
            raise ValueError(f"Invalid action '{action}'. Only Action.SETUP and Action.TEARDOWN are supported.")

    @staticmethod
    def build_commands(*cmds: str) -> List[str]:
        out: List[str] = []
        for cmd in cmds:
            if not cmd:
                continue
            if isinstance(cmd, Enum):
                out.append(cmd.value)
            else:
                out.append(cmd)
        return out

    def _escape_question_for_cli(self, text: Optional[str]) -> str:
        """Insert Ctrl-V before each '?' so IOS treats it literally.
        This affects only the sent command; running-config will show the plain '?'.
        """
        if not text:
            return ""
        return text.replace("?", "\x16?")

    def config_has_strings(self, output: str, *strings: str) -> bool:
        return all(s in output for s in strings)

    def _render_radius_key(self, secret: str, secret_type: Optional[str] = None) -> str:
        """Render the key line, omitting type when not provided.
        Examples:
          _render_radius_key("aristo") -> "key aristo"
          _render_radius_key("aristo", "0") -> "key 0 aristo"
        """
        if not secret:
            return ""
        escaped = self._escape_question_for_cli(secret)
        if secret_type is None:
            return f"key {escaped}"
        return f"key {secret_type} {escaped}"

    def _extract_radius_secret(self, output: str) -> Optional[str]:
        """Extract the RADIUS server secret from a exsting running-config section.
        Matches lines like:
            'key aristo'
            'key 0 aristo'
            'key 7 094F4C1B5A' (encrypted)
        Returns the secret text after the optional type code.
        """
        m = re.search(r"(?mi)^\s*key(?:\s+(?:0|7))?\s+(.*)$", output)
        if not m:
            return None
        token = m.group(1).strip()
        if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
            return token[1:-1]
        log.debug(f"Extracted RADIUS secret: {token}")
        return token

    def _extract_coa_secret(self, output: str, server_ip: Optional[str] = None) -> Optional[str]:
        """Extract the CoA (dynamic-author) client secret from running-config.
        Matches lines like:
            'client 10.16.177.66 server-key aristo123'
        When server_ip is provided, returns the secret for that client IP; otherwise
        returns the first matched secret.
        """
        pattern = r"(?mi)^\s*client\s+(?P<ip>\S+)\s+server-key\s+(?P<secret>.+)$"
        for m in re.finditer(pattern, output):
            ip = m.group("ip").strip()
            secret = m.group("secret").strip()
            if server_ip is None or ip == server_ip:
                if len(secret) >= 2 and secret[0] == secret[-1] and secret[0] in ("'", '"'):
                    secret = secret[1:-1]
                log.debug(f"Extracted CoA secret for {ip}: {secret}")
                return secret
        return None

    def _is_valid_coa_secret(self, secret: str) -> bool:
        """Validate CoA secret: anything except spaces/whitespace.
        Returns True when the secret contains no whitespace characters.
        """
        return bool(secret) and bool(re.match(r"^\S+$", secret))

    def _configure_dot1x_system_auth_control(self) -> bool:
        """Configure dot1x system-auth-control globally. This is setup-only, no teardown needed."""
        try:
            # Check if dot1x system-auth-control is already enabled
            running_config = self.exec_command(RadiusCmd.SHOW_DOT1X.value)
            if RadiusCmd.DOT1X_GLOBAL in running_config:
                log.info(f"{RadiusCmd.DOT1X_GLOBAL.value} already enabled on Cisco switch {self.ip}")
                return True

            # Enable dot1x system-auth-control
            commands = self.build_commands(RadiusCmd.DOT1X_GLOBAL)
            self.exec_command(commands)
            log.info(f"Succeed to setup {RadiusCmd.DOT1X_GLOBAL.value} on Cisco switch {self.ip}")
            return True

        except Exception as e:
            log.error(f"Failed to setup {RadiusCmd.DOT1X_GLOBAL.value} on Cisco switch {self.ip}: {e}")
            return False

    def _generate_radius_server_name(self, server_ip: str) -> str:
        """Generate a server name from IP address, handling both IPv4 and IPv6. Cached for efficiency."""
        # Return cached name if already generated
        if self._radius_server_name:
            return self._radius_server_name

        try:
            ip_obj = ipaddress.ip_address(server_ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                # IPv4: use last 2 parts (e.g., 192.168.1.10 -> 1-10)
                parts = server_ip.split(".")
                server_name = f"{self._radius_server_prefix}-ipv4-{parts[-2]}-{parts[-1]}"
            else:
                # IPv6: use 4th part and last part
                # Expand the address to get all parts
                expanded = ip_obj.exploded
                parts = expanded.split(":")
                if len(parts) >= 4:
                    # Use 4th part and last part
                    server_name = f"{self._radius_server_prefix}-ipv6-{parts[3]}-{parts[-1]}"
                else:
                    # Fallback for short IPv6
                    server_name = f"{self._radius_server_prefix}-ipv6-{parts[0]}-{parts[-1]}"
            self._radius_server_name = server_name
            return self._radius_server_name
        except (ValueError, IndexError) as err:
            log.error(f"Invalid IP address format: {server_ip}")
            raise ValueError(f"Invalid IP address format: {server_ip}") from err

    def _configure_radius_server(
        self,
        action: Action,
        server_ip: str,
        secret: Optional[str] = None,
        timeout: int = 5,
        retransmit: int = 3,
        secret_type: Optional[str] = None,
    ) -> bool:
        """Configure or remove RADIUS server on Cisco switch."""
        self._validate_action(action)
        radius_server_exists = False
        try:
            ip_obj = ipaddress.ip_address(server_ip)
            ip_family = "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6"
            expected_config = self.build_commands(
                RadiusCmd.RADIUS_SERVER.render(name=self._radius_server_name),
                RadiusCmd.RADIUS_ADDRESS.render(ip_family=ip_family, ip=server_ip),
            )
            running_config = self.exec_command(RadiusCmd.SHOW_RADIUS_SERVER.render(name=self._radius_server_name), log_output=True, timeout=60)
            if action == Action.SETUP:
                if not secret:
                    log.error("Secret is required when setting up RADIUS server")
                    return False
                expected_config.append(self._render_radius_key(secret=secret, secret_type=secret_type))
                # 1) If another server already has the same address/ports, remove the address line from it
                if self._setup_count == 1:
                    conflict_server = self._find_radius_server_by_address(expected_config[1])
                    if conflict_server and conflict_server != self._radius_server_name:
                        self._original_radius_server_name = conflict_server
                        log.info(
                            f"Detected address conflict: will back up {self._original_radius_server_name} then remove address"
                        )
                        self._remove_address_from_radius_server(self._original_radius_server_name, expected_config[1])
                current_secret = self._extract_radius_secret(running_config)
                radius_server_exists = (
                    self.config_has_strings(running_config, expected_config[0], expected_config[1], expected_config[2])
                    and current_secret == secret
                )
                if timeout != 5:
                    radius_server_exists = radius_server_exists and self.config_has_strings(
                        running_config,
                        f"timeout {timeout}",
                    )
                else:
                    radius_server_exists = radius_server_exists and (
                        self.config_has_strings(running_config, f"timeout {timeout}")
                        or not self.config_has_strings(running_config, "timeout")
                    )
                if retransmit != 3:
                    radius_server_exists = radius_server_exists and self.config_has_strings(
                        running_config,
                        f"retransmit {retransmit}",
                    )
                else:
                    radius_server_exists = radius_server_exists and (
                        self.config_has_strings(running_config, f"retransmit {retransmit}")
                        or not self.config_has_strings(running_config, "retransmit")
                    )
                if radius_server_exists:
                    log.info(f"RADIUS server {self._radius_server_name} already exists on {self.ip}")
                    return True

                commands_non_secret = self.build_commands(
                    RadiusCmd.AAA_NEW_MODEL,
                    expected_config[0],
                    expected_config[1],
                    *([RadiusCmd.RADIUS_TIMEOUT.render(timeout=timeout)] if timeout != 5 else []),
                    *([RadiusCmd.RADIUS_RETRANSMIT.render(retransmit=retransmit)] if retransmit != 3 else []),
                )
                self.exec_command(commands_non_secret, log_output=True)

                commands_with_secret = self.build_commands(expected_config[0], expected_config[2])
                self.exec_command(commands_with_secret)

            else:  # teardown
                radius_server_exists = self._radius_server_name in running_config
                if not radius_server_exists:
                    log.info(f"RADIUS server {self._radius_server_name} not configured on {self.ip}, skipping teardown")
                    return True
                if self._original_radius_server_name:
                    commands = ["no " + expected_config[0]]
                    self.exec_command(commands)                    
                    self._restore_address_to_radius_server(self._original_radius_server_name, expected_config[1])
                else:    
                    log.info(f"RADIUS server {self._radius_server_name} was configured on {self.ip} before setup, skipping teardown")
                    return True
            log.info(f"Succeed to {action.name.lower()} RADIUS server {self._radius_server_name} on Cisco switch {self.ip}")
            return True

        except Exception as e:
            log.error(f"Failed to {action.name.lower()} RADIUS server {self._radius_server_name} on Cisco switch {self.ip}: {e}")
            return False

    def _configure_radius_group(self, action: Action, group_name: str, server_name: str, deadtime: int = 3) -> bool:
        """Configure or remove RADIUS server group."""
        self._validate_action(action)
        radius_group_exists = False
        try:
            # Check if group already exists
            running_config = self.exec_command(RadiusCmd.SHOW_RADIUS_GROUP.render(group=group_name), log_output=True)
            # Check if group has other server(s) configured
            server_count = running_config.count("server name")
            if action == Action.SETUP:
                if server_count == 1 and self.config_has_strings(running_config, group_name, server_name, f"deadtime {deadtime}"):
                    radius_group_exists = True
                if radius_group_exists:
                    log.info(f"RADIUS group {group_name} already exists on {self.ip}")
                    return True

                commands = self.build_commands(
                    RadiusCmd.RADIUS_GROUP.render(group=group_name),
                    RadiusCmd.RADIUS_GROUP_SERVER.render(server=server_name),
                    RadiusCmd.RADIUS_GROUP_DEADTIME.render(deadtime=deadtime),
                )
                if (server_count == 1 and not self.config_has_strings(running_config, server_name)) or server_count > 1:
                    if self._setup_count == 1 and not self._original_radius_server_group:
                        log.warning(f"{group_name} has an existing configuration, Backing up original group configuration.")
                        self._original_radius_server_group = running_config
                    # Remove existing group before recreating with our server
                    commands.insert(0, "no " + RadiusCmd.RADIUS_GROUP.render(group=group_name))
                self.exec_command(commands, log_output=True)

            else:  # teardown
                radius_group_exists = group_name in running_config
                if not radius_group_exists:
                    log.info(f"RADIUS group {group_name} not configured on {self.ip}, skipping teardown")
                    return True
                if self._original_radius_server_group:
                    # Restore original group config
                    commands = ["no " + RadiusCmd.RADIUS_GROUP.render(group=group_name)]
                    for line in self._original_radius_server_group.splitlines():
                        stripped = line.strip()
                        if stripped:
                            commands.append(stripped)
                    self.exec_command(commands, log_output=True)
                else:    
                    log.info(f"RADIUS group {group_name} was configured on {self.ip} before setup, skipping teardown")
                    return True                    
            log.info(f"Succeed to {action.name.lower()} RADIUS group {group_name} on Cisco switch {self.ip}")
            return True

        except Exception as e:
            log.error(f"Failed to {action.name.lower()} RADIUS group {group_name} on Cisco switch {self.ip}: {e}")
            return False

    def _configure_radius_aaa(self, action: Action, group_name: str, aaa_auth_type: str) -> bool:
        """Configure or remove AAA authentication & authorization & accounting for dot1x."""
        self._validate_action(action)
        commands = self.build_commands(
            RadiusCmd.AAA_AUTH.render(auth_type=aaa_auth_type, group=group_name),
            RadiusCmd.AAA_AUTHZ.render(group=group_name),
            RadiusCmd.AAA_ACCT.render(auth_type=aaa_auth_type, group=group_name),
        )
        try:
            running_config = self.exec_command(RadiusCmd.SHOW_AAA.value, log_output=True)
            radius_aaa_exists = self.config_has_strings(running_config, *commands)

            # On first setup, snapshot the original AAA state so teardown can restore it
            if self._setup_count == 1 and not self._original_radius_aaa:
                self._original_radius_aaa = running_config

            if action == Action.SETUP:
                if radius_aaa_exists:
                    log.info(f"AAA already exists with group {group_name} on {self.ip}")
                    return True
                self.exec_command(commands, log_output=True)
                log.info(f"Succeed to setup AAA for group {group_name} on Cisco switch {self.ip}")
                return True

            else:  # teardown
                if not radius_aaa_exists:
                    log.info(f"AAA not configured with group {group_name} on {self.ip}, skipping teardown")
                    return True
                # If original already had our group's commands, setup made no changes — skip teardown
                if self.config_has_strings(self._original_radius_aaa, *commands):
                    log.info(f"AAA was already configured with group {group_name} before setup, skipping teardown")
                    return True
                # Remove our group's commands, then restore the original AAA lines
                teardown_commands = ["no " + cmd for cmd in commands]
                for line in self._original_radius_aaa.splitlines():
                    line = line.strip()
                    if line:
                        teardown_commands.append(line)
                self.exec_command(teardown_commands, log_output=True)
                log.info(f"Succeed to teardown AAA to original state on Cisco switch {self.ip}")
                return True

        except Exception as e:
            log.error(f"Failed to {action.name.lower()} AAA for group {group_name} on Cisco switch {self.ip}: {e}")
            return False

    def _configure_radius_coa(self, action: Action, server_ip: str, secret: Optional[str] = None) -> bool:
        """Configure or remove RADIUS CoA dynamic-author client.
        Setup: ensure 'aaa server radius dynamic-author' and 'client <ip> server-key <secret>' exist.
        Teardown: only remove the client line: 'no client <ip>'.
        """
        self._validate_action(action)
        radius_coa_exists = False
        try:
            running_config = self.exec_command(RadiusCmd.SHOW_COA.value, log_output=True)
            radius_coa_exists = bool(re.search(rf"(?mi)^\s*client\s+{re.escape(server_ip)}\b", running_config))
            current_secret = self._extract_coa_secret(running_config, server_ip)
            if action == Action.SETUP:
                if radius_coa_exists:
                    if self._setup_count == 1:
                        self._original_radius_coa_exist = True
                        self._original_radius_coa_secret = current_secret
                    if secret is not None and current_secret == secret:
                        log.info(f"RADIUS dynamic-author client {server_ip} already configured with same secret on {self.ip}")
                        return True
                else:
                    if self._setup_count == 1:
                        self._original_radius_coa_exist = False
                        self._original_radius_coa_secret = None
                if secret is None:
                    log.error("Secret is required for CoA setup")
                    return False
                if not self._is_valid_coa_secret(secret):
                    log.warning(f"Skipping CoA setup for {server_ip}: secret contains whitespace")
                    return True
                escaped_secret = self._escape_question_for_cli(secret)
                commands = self.build_commands(
                    RadiusCmd.COA_ENTER,
                    f"client {server_ip} server-key {escaped_secret}",
                )
            else:
                if not radius_coa_exists:
                    log.info(f"RADIUS dynamic-author client {server_ip} not configured on {self.ip}")
                    return True
                # If it existed before setup and we changed the secret, restore original; otherwise preserve.
                if self._original_radius_coa_exist:
                    if self._original_radius_coa_secret is not None and current_secret != self._original_radius_coa_secret:
                        escaped_secret = self._escape_question_for_cli(self._original_radius_coa_secret)
                        log.info(f"Restoring original CoA secret {self._original_radius_coa_secret} for client {server_ip}")
                        commands = self.build_commands(
                            RadiusCmd.COA_ENTER,
                            f"client {server_ip} server-key {escaped_secret}",
                        )
                    else:
                        log.info(f"Preserving RADIUS dynamic-author client {server_ip} as it existed before setup, skipping teardown")
                        return True
                else:
                    commands = self.build_commands(
                        RadiusCmd.COA_ENTER,
                        RadiusCmd.COA_CLIENT_NO.render(ip=server_ip),
                    )
            self.exec_command(commands, log_output=True)
            log.info(f"Succeed to {action.name.lower()} RADIUS dynamic-author client {server_ip} on Cisco switch {self.ip}")
            return True
        except Exception as e:
            log.error(f"Failed to {action.name.lower()} RADIUS dynamic-author client {server_ip} on Cisco switch {self.ip}: {e}")
            return False

    def _configure_dot1x_on_port(self, action: Action, port: str, mab: bool = False, vlan: Optional[int] = None) -> bool:
        """Configure or remove 802.1x/MAB on a specific port.

        Args:
            action: Action.SETUP or Action.TEARDOWN
            port: Switch port
            mab: If True, use MAB instead of dot1x pae authenticator
            vlan: VLAN ID for the port
        """
        self._validate_action(action)

        try:
            setup_commands = [RadiusCmd.INTERFACE_PORT.render(port=port)]
            if port not in self._teardown_commands_on_port:
                self._teardown_commands_on_port[port] = [RadiusCmd.INTERFACE_PORT.render(port=port)]

            # Get current interface configuration
            if action == Action.SETUP:
                current_config = self.exec_command(RadiusCmd.SHOW_INTERFACE.render(port=port), log_output=True)
                access_vlan_prefix = RadiusCmd.SW_ACCESS_VLAN.value.split("{")[0].strip()
                vlan_match = re.search(rf"{access_vlan_prefix} (\d+)", current_config)
                current_vlan = 0
                if vlan_match:
                    current_vlan = int(vlan_match.group(1))
                if self._original_vlan == 4095:
                    self._original_vlan = current_vlan
                if self._original_mab_state.get(port) is None:
                    self._original_mab_state[port] = RadiusCmd.MAB.value in current_config
                if self._original_dot1x_pae_state.get(port) is None:
                    self._original_dot1x_pae_state[port] = RadiusCmd.DOT1X_PAE.value in current_config

                expected_config: List[str] = [
                    RadiusCmd.SW_MODE_ACCESS.value,
                    RadiusCmd.AUTH_PORT_AUTO.value,
                    RadiusCmd.AUTH_PERIODIC.value,
                ]

                # mab=True: use MAB instead of dot1x pae authenticator
                # mab=False: use dot1x pae authenticator (default)
                if mab:
                    expected_config.append(RadiusCmd.MAB.value)
                else:
                    expected_config.append(RadiusCmd.DOT1X_PAE.value)

                # Only add VLAN config if vlan parameter is provided
                if vlan is None and current_vlan is None:
                    log.error(
                        f"Please set parameter vlan since port {port} has no existing VLAN configured on Cisco switch {self.ip}"
                    )
                    return False
                elif vlan is not None and vlan != current_vlan:
                    expected_config.insert(1, RadiusCmd.SW_ACCESS_VLAN.render(vlan=vlan))
                else:
                    expected_config.insert(1, RadiusCmd.SW_ACCESS_VLAN.render(vlan=current_vlan))

                for cmd in expected_config:
                    cmd_text = cmd.value if isinstance(cmd, Enum) else cmd
                    if cmd_text not in current_config:
                        setup_commands.append(cmd_text)
                        self._append_teardown_for_cmd(port, cmd_text, access_vlan_prefix, vlan)

                # If switching to MAB, remove dot1x pae if it exists
                if mab and RadiusCmd.DOT1X_PAE.value in current_config:
                    setup_commands.append(f"no {RadiusCmd.DOT1X_PAE.value}")
                    self._teardown_commands_on_port[port].append(RadiusCmd.DOT1X_PAE.value)

                # If switching to dot1x, remove MAB if it exists
                if not mab and RadiusCmd.MAB.value in current_config:
                    setup_commands.append(f"no {RadiusCmd.MAB.value}")

                if len(setup_commands) == 1:
                    log.info(f"Port {port} already configured on Cisco switch {self.ip}")
                    return True

                self.exec_command(setup_commands, log_output=True)

            else:  # teardown
                if self._original_mab_state.get(port) is not None:
                    self._teardown_commands_on_port[port].append(
                        RadiusCmd.MAB.value if self._original_mab_state[port] else f"no {RadiusCmd.MAB.value}"
                    )
                if self._original_dot1x_pae_state.get(port) is not None:
                    self._teardown_commands_on_port[port].append(
                        RadiusCmd.DOT1X_PAE.value if self._original_dot1x_pae_state[port] else f"no {RadiusCmd.DOT1X_PAE.value}"
                    )                                    
                if port not in self._teardown_commands_on_port or len(self._teardown_commands_on_port[port]) == 1:
                    log.info(f"Port {port} has been configured on Cisco switch {self.ip} before setup, skipping teardown")
                    return True
                else:                    
                    self.exec_command(self._teardown_commands_on_port[port], log_output=True)
                # Clear stored per-port teardown config to avoid reuse
                self._teardown_commands_on_port.pop(port, None)

            log.info(f"Succeed to {action.name.lower()} port config on {port} on Cisco switch {self.ip}")
            return True

        except Exception as e:
            log.error(f"Failed to {action.name.lower()} port config on {port} on Cisco switch {self.ip}: {e}")
            return False

    def _append_teardown_for_cmd(self, port: str, cmd: str, access_vlan_prefix: str, vlan: Optional[int]) -> None:
        """Append appropriate teardown command(s) for a given configuration command.
        - For VLAN changes, restore original or remove if none existed.
        - For non-MAB commands, add a 'no <cmd>' line.
        """
        # VLAN restoration logic
        if str(cmd).startswith(access_vlan_prefix) and vlan is not None:
            if self._original_vlan == 0:
                if f"no {access_vlan_prefix}" not in self._teardown_commands_on_port[port]:
                    self._teardown_commands_on_port[port].append(f"no {access_vlan_prefix}")
            elif self._original_vlan != 0:
                restored = RadiusCmd.SW_ACCESS_VLAN.render(vlan=self._original_vlan)
                if restored not in self._teardown_commands_on_port[port]:
                    self._teardown_commands_on_port[port].append(restored)
            return
        # Generic teardown for non-MAB commands
        if cmd != RadiusCmd.MAB.value:
            self._teardown_commands_on_port[port].append(f"no {cmd}")

    def _find_radius_server_by_address(self, address_line: str) -> Optional[str]:
        """Return the radius server name that currently owns the given address line, if any."""
        output = self.exec_command(RadiusCmd.SHOW_RADIUS_SERVER_ALL.value)
        current_server: Optional[str] = None
        for line in output.splitlines():
            s = line.rstrip()
            if s.startswith("radius server"):
                current_server = s.split("radius server", 1)[1].strip()
                continue
            if current_server and s.strip().startswith("address "):
                if address_line.strip() == s.strip():
                    return current_server
        return None

    def _remove_address_from_radius_server(self, server_name: str, address_line: str) -> None:
        """Enter the given radius server and remove the exact address line."""
        cmds = [
            RadiusCmd.RADIUS_SERVER.render(name=server_name),
            f"no {address_line}",
        ]
        self.exec_command(cmds)

    def _restore_address_to_radius_server(self, server_name: str, address_line: str) -> None:
        """Enter the given radius server and add back the exact address line."""
        cmds = [
            RadiusCmd.RADIUS_SERVER.render(name=server_name),
            address_line,
        ]
        self.exec_command(cmds, log_output=True)
