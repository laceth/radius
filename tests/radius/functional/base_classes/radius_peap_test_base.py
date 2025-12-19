from datetime import datetime
from typing import Union
from framework.log.logger import log
from lib.plugin.radius.models.peap_config import PEAPCredentialsConfig, LauncherScriptConfig
from lib.passthrough import utils as passthrough_utils
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile
from tests.radius.radius_test_base import RadiusTestBase


class RadiusPeapTestBase(RadiusTestBase):

    def __init__(self, ca, em, radius, switch, passthrough, version="1.0.0"):
        super().__init__(ca, em, radius, switch, passthrough, version)
        self.peap_config = PEAPCredentialsConfig()

    def do_setup(self):
        """Setup phase: prepare test environment"""
        log.info("=== Starting PEAP Credentials Setup ===")

        # Log configuration
        log.info(f"Local script path: {self.peap_config.local_script_path}")
        log.info(f"Remote scripts path: {self.peap_config.scripts_path}")
        log.info(f"Remote logs path: {self.peap_config.logs_path}")
        log.info(f"NIC name: {self.peap_config.nicname}")

        # Download PsExec if not present
        self.passthrough.download_psexec(
            self.peap_config.pstools_path,
            self.peap_config.psexec_path
        )

    def setup_peap_credentials(self, domain: str = None, username: str = None, password: str = 'aristo') -> None:
        """
        Execute RADIUS PEAP credentials setup on Windows NIC.

        Args:
            domain: PEAP domain (e.g., 'txqalab'). If None, uses peap_config.peap_domain
            username: PEAP username (e.g., 'dotonex'). If None, uses peap_config.peap_user
            password: PEAP password (default: 'aristo')

        This method orchestrates all the steps:
        1. Copy PowerShell script to target machine
        2. Create log directory and file
        3. Get user's session ID
        4. Attach disconnected session if needed
        5. Render and execute launcher script
        6. Wait for completion and verify success

        Raises:
            RuntimeError: If any step fails
        """
        # Apply domain/username/password if provided
        if domain is not None:
            self.peap_config.peap_domain = domain
        if username is not None:
            self.peap_config.peap_user = username
        self.peap_config.peap_password = password

        # Validate configuration
        self.peap_config.validate()

        config = self.peap_config
        passthrough = self.passthrough

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_filename = f"radius_nic_PEAP_credentials_config_{timestamp}.log"
        log_path = f"{config.logs_path}\\{log_filename}"
        script_path = f"{config.scripts_path}\\{config.peap_script_filename}"
        launcher_path = f"{config.scripts_path}\\setup_nic_peap_credentials.ps1"

        log.info(f"Starting RADIUS PEAP credentials setup for user: {config.peap_username}")

        # Step 1: Copy PowerShell script to target machine
        log.info(f"Copying PEAP script to {script_path}")
        passthrough.copy_file_to_remote(config.local_script_path, script_path)

        # Step 2: Create log directory and prepare log file
        log.info(f"Creating log directory: {config.logs_path}")
        passthrough.create_directory(config.logs_path)

        log.info(f"Removing old log file if exists: {log_path}")
        passthrough.remove_file(log_path)

        log.info(f"Creating new log file: {log_path}")
        cmd = f"New-Item -Path '{log_path}' -ItemType File -Force | Out-Null"
        passthrough.execute_command(cmd)

        # Step 3: Get user's session ID
        log.info(f"Getting session ID for user: {passthrough.username}")
        session_id, session_state = passthrough.get_session_id(passthrough.username)

        # Step 4: Attach disconnected session if needed
        passthrough.attach_disconnected_session(session_id, session_state, config.psexec_path)

        # Step 5: Render launcher script
        log.info("Rendering launcher script")
        launcher_config = LauncherScriptConfig.from_peap_config(config, session_id, log_filename)
        launcher_content = self.render_peap_configuration_launcher_script(launcher_config)

        # Write launcher script to remote machine
        log.info(f"Writing launcher script to: {launcher_path}")
        launcher_content_escaped = launcher_content.replace("'", "''")
        passthrough.remove_file(launcher_path)
        cmd = f"Set-Content -Path '{launcher_path}' -Value '{launcher_content_escaped}' -Encoding ASCII"
        passthrough.execute_command(cmd)

        # Verify launcher script was created
        log.info("Verifying launcher script was created")
        cmd = f"Get-Content '{launcher_path}'"
        stdout = passthrough.execute_command(cmd)
        log.debug(f"Launcher script content:\n{stdout}")

        if not stdout.strip():
            raise RuntimeError("Launcher script is empty after rendering")

        # Step 6: Execute the launcher script
        log.info("Executing launcher script")
        cmd = f'& "{launcher_path}"'
        try:
            stdout = passthrough.execute_command(cmd)
            log.info("Launcher script executed successfully")
            if stdout:
                log.debug(f"Launcher stdout: {stdout}")
        except RuntimeError as e:
            log.info(f"Launcher script execution returned: {e}")

        # Step 7: Wait for script completion
        log.info("Waiting for PEAP configuration script to complete")
        success = passthrough.wait_for_log_completion(log_path, timeout=500, interval=5)

        if not success:
            try:
                log_content = passthrough.read_log_file(log_path)
            except RuntimeError:
                log_content = "<Unable to read log file>"

            raise RuntimeError(
                f"Script did not complete within timeout.\n"
                f"Log content so far:\n{log_content}"
            )

        # Step 8: Read final log content
        log.info("Reading final log output")
        log_content = passthrough.read_log_file(log_path)
        log.info("RADIUS PEAP credentials setup completed successfully")

        passthrough_utils.verify_log_content(log_content, 'Script Execution Completed')

    def do_teardown(self):
        """Cleanup phase"""
        log.info("=== PEAP Test Teardown ===")
        super().do_teardown()
        log.info("=== Test Complete ===")

    def render_peap_configuration_launcher_script(self, config: LauncherScriptConfig) -> str:
        """
        Render the PowerShell launcher script that will execute the PEAP configuration script.

        Args:
            config: LauncherScriptConfig object containing all script parameters

        Returns:
            Rendered script content
        """
        passthrough = self.passthrough

        # Use PEAP credentials if provided, otherwise use Windows credentials
        peap_user = config.peap_username if config.peap_username else passthrough.username
        peap_pass = config.peap_password if config.peap_password else passthrough.password

        # Render the launcher script template
        template = (
            f"{config.psexec_path} -accepteula -u \"{passthrough.username}\" -p \"{passthrough.password}\" "
            f"-i {config.session_id} -h -d powershell.exe -ExecutionPolicy {config.execution_policy} "
            f"-File \"{config.scripts_path}\\{config.peap_script_filename}\" "
            f"-username \"{peap_user}\" "
            f"-password \"{peap_pass}\" "
            f"-nicname \"{config.nicname}\" "
            f"-logfile \"{config.logs_path}\\{config.log_filename}\""
        )
        return template

    # =========================================================================
    # LAN Profile Management
    # =========================================================================

    def configure_lan_profile(self, auth_nic_profile: AuthNicProfile = AuthNicProfile.PEAP):
        """
        Configure the LAN profile on the Windows endpoint.

        Args:
            auth_nic_profile: NIC profile type to configure (default: AuthNicProfile.PEAP)

        This method:
        1. Sets the auth_nic_profile on the config
        2. Copies the LAN profile XML to the remote machine
        3. Deletes any existing LAN profile from the NIC
        4. Adds the new LAN profile to the NIC
        """
        # Set the NIC profile type
        self.peap_config.auth_nic_profile = auth_nic_profile

        config = self.peap_config
        passthrough = self.passthrough

        log.info(f"=== Configuring LAN Profile: {auth_nic_profile.name} ===")

        # Copy LAN profile to remote machine
        remote_profile_path = f"{config.profiles_path}\\{config.lan_profile_filename}"
        passthrough.copy_file_to_remote(
            config.local_lan_profile_path,
            remote_profile_path
        )

        # Delete existing profile (if any)
        passthrough.delete_lan_profile(config.nicname)

        # Add new profile
        passthrough.add_lan_profile(remote_profile_path, config.nicname)

        log.info("=== LAN Profile Configuration Complete ===")

    # =========================================================================
    # NIC Management
    # =========================================================================

    def toggle_nic(self):
        """Toggle the NIC (disable then enable) to trigger re-authentication."""
        self.passthrough.toggle_nic(self.peap_config.nicname)

    def disable_nic(self):
        """Disable the NIC."""
        self.passthrough.disable_nic(self.peap_config.nicname)

    def enable_nic(self):
        """Enable the NIC."""
        self.passthrough.enable_nic(self.peap_config.nicname)

    # =========================================================================
    # Authentication Assertions
    # =========================================================================

    def assert_authentication_successful(self,
                                         expected_status: Union[AuthenticationStatus, str] = AuthenticationStatus.SUCCEEDED,
                                         timeout: int = 90):
        """
        Assert that authentication was successful by waiting for NIC authentication status.

        Args:
            expected_status: Expected authentication status (default: AuthenticationStatus.SUCCEEDED)
            timeout: Maximum time to wait in seconds (default: 90)

        Raises:
            AssertionError: If NIC does not reach expected status within timeout
        """
        self.passthrough.wait_for_nic_authentication(
            self.peap_config.nicname,
            expected_status=expected_status,
            timeout=timeout
        )

