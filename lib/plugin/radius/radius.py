import time
from datetime import datetime
from framework.log.logger import log

# Commands
DOT1X_PLUGIN_RESTART_CMD = "fstool dot1x restart"
DOT1X_PLUGIN_STATUS_CMD = "fstool dot1x status"

# Default
DEFAULT_RADIUS_RESTART_TIMEOUT = 60
DEFAULT_POLL_INTERVAL = 5


class Radius:
    version = "1.0.0"
    platform = None

    def __init__(self, platform, version="1.0.0", username=None, password=None):
        self.platform = platform
        self.version = version
        self.username = username
        self.password = password

    def exec_cmd(self, command: str, timeout: int = 15) -> str:
        return self.platform.exec_command(command, timeout)

    def plugin_running(self) -> bool:
        log.info("Checking if 802.1X plugin is running on RADIUS server")
        status_output = self.exec_cmd(DOT1X_PLUGIN_STATUS_CMD)
        if "is running" in status_output:
            log.info("RADIUS server is running")
            return True
        else:
            log.error("RADIUS server is not running")
            return False

    def restart_dot1x_plugin(self, timeout: int = DEFAULT_RADIUS_RESTART_TIMEOUT,
                             interval: int = DEFAULT_POLL_INTERVAL) -> None:
        log.info("Restarting 802.1X plugin on RADIUS server")
        self.exec_cmd(DOT1X_PLUGIN_RESTART_CMD)
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.plugin_running():
                log.info("802.1X plugin restarted successfully and is running")
                return
            log.info(f"Waiting for plugin to start... Retrying in {interval} seconds")
            time.sleep(interval)

        log.error("802.1X plugin failed to restart within the timeout period")

    def set_radius_pre_admission_rule(self, rule: str) -> None:
        log.info(f"Setting RADIUS pre-admission rule: {rule}")

    def render_launcher_script(self, passthrough, session_id: str, log_filename: str,
                               psexec_path: str,
                               execution_policy: str,
                               scripts_path: str,
                               peap_script_filename: str,
                               nicname: str,
                               logs_path: str,
                               peap_username: str = None,
                               peap_password: str = None) -> str:
        """
        Render the PowerShell launcher script that will execute the PEAP configuration script.

        Args:
            passthrough: WindowsPassthrough instance for accessing credentials
            session_id: Windows session ID to run the script in
            log_filename: Log file name for script output
            psexec_path: Path to psexec executable
            execution_policy: PowerShell execution policy
            scripts_path: Path to scripts directory
            peap_script_filename: PEAP script filename
            domain: Domain name
            nicname: Network interface name
            logs_path: Path to logs directory
            peap_username: PEAP username
            peap_password: PEAP password

        Returns:
            Rendered script content
        """
        # Use PEAP credentials if provided, otherwise use Windows credentials
        peap_user = peap_username if peap_username else passthrough.username
        peap_pass = peap_password if peap_password else passthrough.password

        # Render the launcher script template
        # PsExec uses Windows credentials (passthrough.username/password)
        # PowerShell script receives PEAP credentials (peap_user/peap_pass)
        template = (
            f"{psexec_path} -accepteula -u \"{passthrough.username}\" -p \"{passthrough.password}\" "
            f"-i {session_id} -h -d powershell.exe -ExecutionPolicy {execution_policy} "
            f"-File \"{scripts_path}\\{peap_script_filename}\" "
            f"-username \"{peap_user}\" "
            f"-password \"{peap_pass}\" "
            f"-nicname \"{nicname}\" "
            f"-logfile \"{logs_path}\\{log_filename}\""
        )
        return template

    def wait_for_log_completion(self, passthrough, log_path: str, timeout: int = 500, interval: int = 5) -> bool:
        """
        Wait for the script execution to complete by monitoring the log file.

        Args:
            passthrough: WindowsPassthrough instance for executing commands
            log_path: Path to the log file on remote machine
            timeout: Maximum time to wait in seconds
            interval: Check interval in seconds

        Returns:
            True if completion marker found, False if timeout
        """
        start_time = time.time()
        retries = 0
        max_retries = timeout // interval

        log.info(f"Waiting for script completion (checking every {interval}s, max {timeout}s)")

        while retries < max_retries:
            try:
                log_path_normalized = log_path.replace('/', '\\')
                cmd = f"Get-Content '{log_path_normalized}'"

                try:
                    stdout = passthrough.execute_command(cmd)
                    if 'Script Execution Completed' in stdout:
                        log.info("Script execution completed successfully")
                        return True
                except RuntimeError:
                    # Log file might not exist yet or other error
                    pass

                retries += 1
                elapsed = time.time() - start_time
                log.debug(f"Attempt {retries}/{max_retries}: Completion marker not found yet (elapsed: {elapsed:.1f}s)")
                time.sleep(interval)

            except Exception as e:
                log.warning(f"Error checking log file: {e}")
                retries += 1
                time.sleep(interval)

        log.error(f"Timeout waiting for script completion after {timeout}s")
        return False

    def read_log_file(self, passthrough, log_path: str) -> str:
        """
        Read and return the content of a log file.

        Args:
            passthrough: WindowsPassthrough instance for executing commands
            log_path: Path to the log file on remote machine

        Returns:
            Log file content

        Raises:
            RuntimeError: If log file cannot be read
        """
        log_path_normalized = log_path.replace('/', '\\')
        cmd = f"Get-Content '{log_path_normalized}'"
        stdout = passthrough.execute_command(cmd)
        return stdout

    def setup_peap_credentials(self, passthrough, local_script_path: str,
                               scripts_path: str,
                               logs_path: str,
                               peap_script_filename: str,
                               psexec_path: str,
                               execution_policy: str,
                               nicname: str,
                               peap_username: str,
                               peap_password: str) -> str:
        """
        Main method to execute RADIUS PEAP credentials setup on Windows NIC.

        This method orchestrates all the steps:
        1. Copy PowerShell script to target machine
        2. Create log directory and file
        3. Get user's session ID
        4. Attach disconnected session if needed
        5. Render and execute launcher script
        6. Wait for completion and verify success
        7. Return log output

        Args:
            passthrough: WindowsPassthrough instance for file transfer and command execution
            local_script_path: Path to the local PEAP credentials PowerShell script
                              (radius_nic_PEAP_credentials_config.ps1)
            scripts_path: Remote path for scripts
            logs_path: Remote path for logs
            peap_script_filename: Name of the PEAP script file
            psexec_path: Path to psexec executable
            execution_policy: PowerShell execution policy
            domain: Domain name (can be None)
            nicname: Network interface name (e.g., 'pciPassthru0')
            peap_username: PEAP username (if different from Windows user, e.g., domain\\user)
            peap_password: PEAP password (if different from Windows password)

        Returns:
            Log file content

        Raises:
            RuntimeError: If any step fails
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_filename = f"radius_nic_PEAP_credentials_config_{timestamp}.log"
        log_path = f"{logs_path}\\{log_filename}"
        script_path = f"{scripts_path}\\{peap_script_filename}"
        launcher_path = f"{scripts_path}\\setup_nic_peap_credentials.ps1"

        log.info("Starting RADIUS PEAP credentials setup")

        # Step 1: Copy PowerShell script to target machine
        log.info(f"Copying PEAP script to {script_path}")
        passthrough.copy_file_to_remote(local_script_path, script_path)

        # Step 2: Create log directory and prepare log file
        log.info(f"Creating log directory: {logs_path}")
        passthrough.create_directory(logs_path)

        log.info(f"Removing old log file if exists: {log_path}")
        passthrough.remove_file(log_path)

        log.info(f"Creating new log file: {log_path}")
        cmd = f"New-Item -Path '{log_path}' -ItemType File -Force | Out-Null"
        passthrough.execute_command(cmd)

        # Step 3: Get user's session ID
        log.info(f"Getting session ID for user: {passthrough.username}")
        session_id, session_state = passthrough.get_session_id(passthrough.username)

        # Step 4: Attach disconnected session if needed
        passthrough.attach_disconnected_session(session_id, session_state, psexec_path)

        # Step 5: Render launcher script
        log.info("Rendering launcher script")
        launcher_content = self.render_launcher_script(
            passthrough=passthrough,
            session_id=session_id,
            log_filename=log_filename,
            psexec_path=psexec_path,
            execution_policy=execution_policy,
            scripts_path=scripts_path,
            peap_script_filename=peap_script_filename,
            nicname=nicname,
            logs_path=logs_path,
            peap_username=peap_username,
            peap_password=peap_password
        )

        # Write launcher script to remote machine
        log.info(f"Writing launcher script to: {launcher_path}")

        # For safety, write the launcher script using Set-Content with proper encoding
        # This avoids command line length issues with here-strings
        launcher_content_escaped = launcher_content.replace("'", "''")  # Escape single quotes for PowerShell

        # Delete old launcher if exists using the dedicated remove_file method
        passthrough.remove_file(launcher_path)

        # Write the content using Set-Content
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
            # The launcher uses -d flag with PsExec, so it may return immediately
            # This is expected behavior, we'll wait for the log file instead
            log.info(f"Launcher script execution returned: {e}")

        # Note: The launcher uses -d flag with PsExec, so it returns immediately
        # We need to wait for the actual script to complete by monitoring the log

        # Step 7: Wait for script completion
        log.info("Waiting for PEAP configuration script to complete")
        success = self.wait_for_log_completion(passthrough, log_path, timeout=500, interval=5)

        if not success:
            # Read whatever is in the log file
            try:
                log_content = self.read_log_file(passthrough, log_path)
            except RuntimeError:
                log_content = "<Unable to read log file>"

            raise RuntimeError(
                f"Script did not complete within timeout.\n"
                f"Log content so far:\n{log_content}"
            )

        # Step 8: Read final log content
        log.info("Reading final log output")
        log_content = self.read_log_file(passthrough, log_path)

        log.info("RADIUS PEAP credentials setup completed successfully")
        return log_content

    def download_psexec(self, passthrough, pstools_path: str, psexec_path: str):
        """
        Download and extract PsExec on the remote Windows machine if not already present.

        Args:
            passthrough: WindowsPassthrough instance for file operations
            pstools_path: Path to PSTools directory (e.g., 'C:\\PSTools')
            psexec_path: Full path to PsExec.exe (e.g., 'C:\\PSTools\\PsExec.exe')

        Raises:
            RuntimeError: If download or extraction fails
        """
        log.info("=== Checking/Downloading PsExec ===")

        # Early return if PsExec already exists
        if self._check_file_exists(passthrough, psexec_path):
            log.info(f"[OK] PsExec already exists at: {psexec_path}")
            return

        log.info("PsExec not found, downloading from Microsoft Sysinternals...")

        # Constants
        PSTOOLS_URL = "https://download.sysinternals.com/files/PSTools.zip"
        zip_path = f"{pstools_path}\\PSTools.zip"

        # Download and extract
        passthrough.create_directory(pstools_path)
        self._download_file(passthrough, PSTOOLS_URL, zip_path)
        self._extract_zip(passthrough, zip_path, pstools_path)

        # Verify and cleanup
        if not self._check_file_exists(passthrough, psexec_path):
            raise RuntimeError(f"PsExec.exe not found after extraction at: {psexec_path}")

        log.info(f"[OK] PsExec is ready at: {psexec_path}")
        self._cleanup_file(passthrough, zip_path)

    def _check_file_exists(self, passthrough, file_path: str) -> bool:
        """Check if a file exists on the remote Windows machine."""
        try:
            result = passthrough.execute_command(f"Test-Path '{file_path}'")
            return result.strip().lower() == 'true'
        except Exception:
            return False

    def _download_file(self, passthrough, url: str, destination: str):
        """Download a file from URL to the remote Windows machine."""
        log.info(f"Downloading from: {url}")
        cmd = f"$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '{url}' -OutFile '{destination}' -UseBasicParsing"
        try:
            passthrough.execute_command(cmd)
            log.info(f"[OK] Downloaded to: {destination}")
        except Exception as e:
            raise RuntimeError(f"Failed to download from {url}: {e}")

    def _extract_zip(self, passthrough, zip_path: str, destination: str):
        """Extract a zip file on the remote Windows machine."""
        log.info(f"Extracting {zip_path}...")
        cmd = f"$ProgressPreference = 'SilentlyContinue'; Expand-Archive -Path '{zip_path}' -DestinationPath '{destination}' -Force"
        try:
            passthrough.execute_command(cmd)
            log.info(f"[OK] Extracted to: {destination}")
        except Exception as e:
            raise RuntimeError(f"Failed to extract {zip_path}: {e}")

    def _cleanup_file(self, passthrough, file_path: str):
        """Remove a file from the remote Windows machine (best effort)."""
        try:
            passthrough.remove_file(file_path)
            log.info(f"[OK] Cleaned up: {file_path}")
        except Exception as e:
            log.warning(f"Could not clean up {file_path}: {e}")

    def verify_log_content(self, log_content: str):
        """
        Verify the log content contains expected success markers.

        Args:
            log_content: The log file content from the PEAP setup

        Raises:
            AssertionError: If required success markers are not found
        """
        log.info("Verifying log content for success markers...")

        # Check for completion marker
        if 'Script Execution Completed' not in log_content:
            raise AssertionError("Log does not contain 'Script Execution Completed' marker")

        log.info("[OK] Found 'Script Execution Completed' marker")

        # Check for common success indicators (adjust based on your script)
        success_indicators = [
            'Script Execution Completed',
        ]

        found_indicators = []
        missing_indicators = []

        for indicator in success_indicators:
            if indicator in log_content:
                found_indicators.append(indicator)
                log.info(f"[OK] Found indicator: {indicator}")
            else:
                missing_indicators.append(indicator)
                log.warning(f"[WARN] Missing indicator: {indicator}")

        # Check for error indicators
        error_indicators = ['Error:', 'Exception:', 'Failed:', 'ERROR:']
        found_errors = []

        for error in error_indicators:
            if error in log_content:
                found_errors.append(error)
                log.warning(f"[WARN] Found error indicator: {error}")

        if found_errors:
            log.warning(f"Warning: Found {len(found_errors)} error indicator(s) in log")

        # Assert that we have the critical completion marker
        assert 'Script Execution Completed' in log_content, \
            "PEAP setup did not complete successfully"

        log.info(f"[OK] Verification complete: {len(found_indicators)}/{len(success_indicators)} indicators found")
