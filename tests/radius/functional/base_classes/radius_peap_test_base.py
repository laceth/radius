from datetime import datetime
from typing import Union

from framework.log.logger import log
from lib.passthrough import utils as passthrough_utils
from lib.passthrough.enums import AuthNicProfile
from lib.plugin.radius.enums import RadiusAuthStatus
from lib.plugin.radius.models.peap_config import PEAPCredentialsConfig
from tests.radius.radius_test_base import RadiusTestBase


class RadiusPeapTestBase(RadiusTestBase):

    def __init__(self, ca, em, radius, switch, passthrough, ad=None, version="1.0.0"):
        super().__init__(ca, em, radius, switch, passthrough, ad, version)
        self.peap_config = PEAPCredentialsConfig()
        self.nicname = self.peap_config.nicname

    def do_setup(self):
        """Setup phase: prepare test environment."""
        log.info("=== Starting PEAP Test Setup ===")

        # Run common setup (cleanup endpoint, configure switch)
        super().do_setup()

        log.info(f"NIC: {self.nicname}")
        self.passthrough.download_psexec(
            self.peap_config.pstools_path,
            self.peap_config.psexec_path
        )

    def do_teardown(self):
        """Cleanup phase."""
        log.info("=== PEAP Test Teardown ===")
        super().do_teardown()

    # =========================================================================
    # Authentication Verification
    # =========================================================================

    def verify_authentication_on_ca(
        self,
        peap_config: PEAPCredentialsConfig = None,
        switch_ip: str = None,
        ca_ip: str = None,
        auth_status: Union[RadiusAuthStatus, str] = RadiusAuthStatus.ACCESS_ACCEPT
    ):
        """
        Verify PEAP authentication properties on CounterAct.
        Extends base class verify_authentication_on_ca with PEAP-specific fields.

        Args:
            peap_config: PEAPCredentialsConfig object containing domain/user info.
                         Defaults to self.peap_config
            switch_ip: Expected Switch IP (dot1x_NAS_addr). Defaults to self.switch.ip
            ca_ip: Expected CounterACT IP (dot1x_auth_appliance). Defaults to self.ca.ipaddress
            auth_status: Expected auth status (dot1x_user_auth_status). Default: RadiusAuthStatus.ACCESS_ACCEPT
        """
        # Get host ID once using base class helper
        host_id = self._get_host_id()
        log.info(f"Verifying PEAP authentication for host: {host_id}")

        # Convert enum to string value if needed
        auth_status_value = auth_status.value if isinstance(auth_status, RadiusAuthStatus) else auth_status

        # Verify common fields using base class helper
        self._verify_common_properties(
            host_id=host_id,
            switch_ip=switch_ip,
            ca_ip=ca_ip,
            auth_state=auth_status_value
        )

        # Use provided config or fall back to instance config
        config = peap_config or self.peap_config

        # Determine tunneled user format (with or without domain prefix)
        tunneled_user = config.peap_username if '\\' in config.peap_username else config.peap_user
        
        # Use "None given" for empty domain
        requested_domain = config.peap_domain if config.peap_domain else "None given"

        # Build PEAP-specific properties check list
        peap_properties_check_list = [
            {"property_field": "dot1x_user_auth_status", "expected_value": auth_status_value},
            {"property_field": "dot1x_rqeuested_domain", "expected_value": requested_domain},
            {"property_field": "dot1x_user", "expected_value": config.peap_user},
            {"property_field": "dot1x_tunneled_user", "expected_value": tunneled_user},
            {"property_field": "dot1x_fr_eap_type", "expected_value": "PEAP"},
            {"property_field": "dot1x_login_type", "expected_value": "dot1x_user_login"},
        ]
        
        # Handle dot1x_domain check based on peap_domain and auth_source configuration
        if config.peap_domain:
            # Domain specified in credentials - check it (case-insensitive)
            peap_properties_check_list.append(
                {"property_field": "dot1x_domain", "expected_value": config.peap_domain, "case_insensitive": True}
            )
        else:
            # No domain in credentials - check if there's a default auth source configured
            auth_source = self.dot1x.get_auth_source_default()
            if auth_source:
                if auth_source == self.default_ad_config.get('ad_name', ''):
                    domain_name = 'TXQALAB'
                if 'TXQALAB2' in auth_source.upper :
                    domain_name = 'TXQALAB2'
                peap_properties_check_list.append(
                    {"property_field": "dot1x_domain", "expected_value": domain_name}
                )
            # If auth_source is empty, skip dot1x_domain check (property won't be present)

        self.ca.check_properties(host_id, peap_properties_check_list)
        log.info("PEAP authentication verification completed successfully")

    def _get_auth_source_default(self) -> str:
        """
        Get the default auth source value from RADIUS server local.properties.
        
        Returns:
            Auth source domain name (e.g., "txqalab-dc1") or empty string if not configured
        """
        try:
            cmd = "grep '^config.auth_source_default.value=' /usr/local/forescout/plugin/dot1x/local.properties"
            output = self.dot1x.exec_cmd(cmd, timeout=10)
            
            # Parse the value after the '=' sign
            if '=' in output:
                value = output.split('=', 1)[1].strip()
                log.info(f"Auth source default: '{value}'")
                return value
            return ""
        except Exception as e:
            log.warning(f"Could not read auth_source_default from local.properties: {e}")
            return ""

    # =========================================================================
    # PEAP Credentials Setup
    # =========================================================================

    def setup_peap_credentials(self, domain: str = 'txqalab', username: str = 'dotonex', password: str = 'aristo'):
        """
        Configure PEAP credentials on Windows NIC.

        Args:
            domain: PEAP domain (default: 'txqalab')
            username: PEAP username (default: 'dotonex')
            password: PEAP password (default: 'aristo')
        """
        self.peap_config.peap_domain = domain
        self.peap_config.peap_user = username
        self.peap_config.peap_password = password
        self.peap_config.validate()

        config = self.peap_config
        log.info(f"Setting up PEAP credentials for: {config.peap_username}")

        # Prepare paths
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_filename = f"radius_nic_PEAP_credentials_config_{timestamp}.log"
        log_path = f"{config.logs_path}\\{log_filename}"
        script_path = f"{config.scripts_path}\\{config.peap_script_filename}"
        launcher_path = f"{config.scripts_path}\\setup_nic_peap_credentials.ps1"

        # Copy script and prepare log directory
        self.passthrough.copy_file_to_remote(config.local_script_path, script_path)
        self.passthrough.create_directory(config.logs_path)
        self.passthrough.remove_file(log_path)
        self.passthrough.execute_command(f"New-Item -Path '{log_path}' -ItemType File -Force | Out-Null")

        # Get session and attach if needed
        session_id, session_state = self.passthrough.get_session_id(self.passthrough.username)
        self.passthrough.attach_disconnected_session(session_id, session_state, config.psexec_path)

        # Create and execute launcher script
        launcher_content = self._render_launcher_script(config, session_id, log_filename)
        self._write_and_execute_launcher(launcher_path, launcher_content)

        # Wait for completion and verify
        if not self.passthrough.wait_for_log_completion(log_path, timeout=500, interval=5):
            log_content = self._safe_read_log(log_path)
            raise RuntimeError(f"Script did not complete within timeout.\nLog:\n{log_content}")

        log_content = self.passthrough.read_log_file(log_path)
        passthrough_utils.verify_log_content(log_content, 'Script Execution Completed')
        log.info("PEAP credentials setup completed")

    def _render_launcher_script(self, config: PEAPCredentialsConfig, session_id: str, log_filename: str) -> str:
        """Render the PowerShell launcher script."""
        return (
            f"{config.psexec_path} -accepteula -u \"{self.passthrough.username}\" -p \"{self.passthrough.password}\" "
            f"-i {session_id} -h -d powershell.exe -ExecutionPolicy {config.execution_policy} "
            f"-File \"{config.scripts_path}\\{config.peap_script_filename}\" "
            f"-username \"{config.peap_username}\" "
            f"-password \"{config.peap_password}\" "
            f"-nicname \"{config.nicname}\" "
            f"-logfile \"{config.logs_path}\\{log_filename}\""
        )

    def _write_and_execute_launcher(self, launcher_path: str, content: str):
        """Write launcher script to remote machine and execute it."""
        self.passthrough.remove_file(launcher_path)
        escaped_content = content.replace("'", "''")
        self.passthrough.execute_command(
            f"Set-Content -Path '{launcher_path}' -Value '{escaped_content}' -Encoding ASCII"
        )
        try:
            self.passthrough.execute_command(f'& "{launcher_path}"')
        except RuntimeError:
            pass  # PsExec with -d returns immediately

    def _safe_read_log(self, log_path: str) -> str:
        """Read log file, returning placeholder if unable."""
        try:
            return self.passthrough.read_log_file(log_path)
        except RuntimeError:
            return "<Unable to read log file>"

    # =========================================================================
    # LAN Profile Management (PEAP-specific override)
    # =========================================================================

    def configure_lan_profile(self, auth_nic_profile: AuthNicProfile = AuthNicProfile.PEAP):
        """Configure LAN profile using PEAP config paths."""
        self.peap_config.auth_nic_profile = auth_nic_profile
        super().configure_lan_profile(
            auth_nic_profile=auth_nic_profile,
            local_profile_path=self.peap_config.local_lan_profile_path,
            remote_profiles_path=self.peap_config.profiles_path
        )

