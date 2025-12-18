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

    def setup_peap_credentials(self) -> str:
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
        launcher_content = self.dot1x.render_peap_configuration_launcher_script(passthrough, launcher_config)

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
        return log_content

    def do_teardown(self):
        """Cleanup phase"""
        log.info("=== PEAP Test Teardown ===")
        super().do_teardown()
        log.info("=== Test Complete ===")

    def assert_peap_setup_successful(self, log_content: str, completion_marker: str = 'Script Execution Completed'):
        """
        Assert that PEAP setup completed successfully.

        Args:
            log_content: The log file content from the PEAP setup
            completion_marker: The marker string that indicates successful completion

        Raises:
            AssertionError: If completion marker is not found
        """
        passthrough_utils.verify_log_content(log_content, completion_marker)

