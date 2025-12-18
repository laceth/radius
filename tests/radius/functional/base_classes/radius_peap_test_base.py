from datetime import datetime
from framework.log.logger import log
from lib.plugin.radius.models.peap_config import PEAPCredentialsConfig, LauncherScriptConfig
from lib.passthrough import utils as passthrough_utils
from tests.radius.radius_test_base import RadiusTestBase


class RadiusPeapTestBase(RadiusTestBase):

    def __init__(self, ca, em, radius, switch, passthrough, version="1.0.0"):
        super().__init__(ca, em, radius, switch, passthrough, version)
        self.peap_config = PEAPCredentialsConfig()

    def do_setup(self):
        """Setup phase: prepare test environment"""
        log.info("=== Starting PEAP Credentials Setup ===")

        # Apply parametrized credentials if provided
        if hasattr(self, 'peap_domain'):
            self.peap_config.peap_domain = self.peap_domain if self.peap_domain else self.peap_config.peap_domain

        if hasattr(self, 'peap_user') and self.peap_user:
            self.peap_config.peap_user = self.peap_user

        # Log configuration
        log.info(f"Local script path: {self.peap_config.local_script_path}")
        log.info(f"Remote scripts path: {self.peap_config.scripts_path}")
        log.info(f"Remote logs path: {self.peap_config.logs_path}")
        log.info(f"NIC name: {self.peap_config.nicname}")
        log.info(f"PEAP username: {self.peap_config.peap_username}")

        # Download PsExec if not present
        passthrough_utils.download_psexec(
            self.passthrough,
            self.peap_config.pstools_path,
            self.peap_config.psexec_path
        )

    def setup_peap_credentials(self) -> None:
        """
        Execute RADIUS PEAP credentials setup on Windows NIC.

        This method orchestrates all the steps:
        1. Copy PowerShell script to target machine
        2. Create log directory and file
        3. Get user's session ID
        4. Attach disconnected session if needed
        5. Render and execute launcher script
        6. Wait for completion and verify success
        7. Return log output

        Returns:
            Log file content

        Raises:
            RuntimeError: If any step fails
        """
        # Validate configuration
        self.peap_config.validate()

        config = self.peap_config
        passthrough = self.passthrough

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_filename = f"radius_nic_PEAP_credentials_config_{timestamp}.log"
        log_path = f"{config.logs_path}\\{log_filename}"
        script_path = f"{config.scripts_path}\\{config.peap_script_filename}"
        launcher_path = f"{config.scripts_path}\\setup_nic_peap_credentials.ps1"

        log.info("Starting RADIUS PEAP credentials setup")

        # Step 1: Copy PowerShell script to target machine
        log.info(f"Copying PEAP script to {script_path}")
        passthrough_utils.copy_file_to_remote(passthrough, config.local_script_path, script_path)

        # Step 2: Create log directory and prepare log file
        log.info(f"Creating log directory: {config.logs_path}")
        passthrough_utils.create_directory(passthrough, config.logs_path)

        log.info(f"Removing old log file if exists: {log_path}")
        passthrough_utils.remove_file(passthrough, log_path)

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
        passthrough_utils.remove_file(passthrough, launcher_path)
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
        success = passthrough_utils.wait_for_log_completion(passthrough, log_path, timeout=500, interval=5)

        if not success:
            try:
                log_content = passthrough_utils.read_log_file(passthrough, log_path)
            except RuntimeError:
                log_content = "<Unable to read log file>"

            raise RuntimeError(
                f"Script did not complete within timeout.\n"
                f"Log content so far:\n{log_content}"
            )

        # Step 8: Read final log content
        log.info("Reading final log output")
        log_content = passthrough_utils.read_log_file(passthrough, log_path)
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

    def configure_lan_profile(self):
        """
        Configure the LAN profile on the Windows endpoint.

        This method:
        1. Copies the LAN profile XML to the remote machine
        2. Deletes any existing LAN profile from the NIC
        3. Adds the new LAN profile to the NIC
        """
        config = self.peap_config
        passthrough = self.passthrough

        log.info("=== Configuring LAN Profile ===")

        # Copy LAN profile to remote machine
        remote_profile_path = f"{config.profiles_path}\\{config.lan_profile_filename}"
        passthrough_utils.copy_file_to_remote(
            passthrough,
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

