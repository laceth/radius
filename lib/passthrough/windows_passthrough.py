        return self.execute_command(cmd, is_ps=False)
from framework.log.logger import log
from lib.passthrough.passthrough_base import PassthroughBase
from lib.passthrough.enums import AuthenticationStatus
import ipaddress
import winrm
import re
import time
from typing import Optional, Tuple, Union


class WindowsPassthrough(PassthroughBase):
    def __init__(self, ip: str, user_name: str, password: str, mac: str, nicname: str = "pciPassthru0"):
        super().__init__(ip, user_name, password, mac, nicname)
        self.win_con = winrm.Session(self.ip, auth=(self.username, self.password), transport='ntlm')

    def execute_command(self, command, is_ps=True):
        try:
            log.info(f"Executing command on WindowsPassthrough: {command}")

            # For PowerShell commands, suppress progress output to avoid CLIXML errors
            if is_ps:
                # Prepend command with $ProgressPreference to suppress progress bars
                command = f"$ProgressPreference = 'SilentlyContinue'; {command}"

            out = self.win_con.run_ps(command) if is_ps else self.win_con.run_cmd(command)
        except Exception as e:
            raise RuntimeError(f"Failed to execute command '{command}': {str(e)}")

        stdout = out.std_out.decode("utf-8", errors="replace").strip()
        stderr = out.std_err.decode("utf-8", errors="replace").strip()

        rc = out.status_code
        ok = (rc == 0)

        # Filter out CLIXML progress messages from stderr
        if stderr:
            # Remove CLIXML progress output which isn't a real error
            if '#< CLIXML' in stderr or 'Preparing modules for first use' in stderr:
                log.debug(f"Filtered PowerShell progress output from stderr")
                # Only keep lines that aren't CLIXML
                stderr_lines = stderr.split('\n')
                stderr = '\n'.join(line for line in stderr_lines
                                   if not line.strip().startswith('<')
                                   and '#< CLIXML' not in line
                                   and 'Preparing modules for first use' not in line)
                stderr = stderr.strip()

        if not ok:
            # Build detailed error message
            error_parts = [f"Command failed (code={rc})"]

            if stdout:
                error_parts.append(f"STDOUT:\n{stdout}")

            if stderr:
                error_parts.append(f"STDERR:\n{stderr}")
            else:
                error_parts.append("STDERR:\n<empty>")

            # Add the actual command for debugging (truncate if too long)
            cmd_display = command if len(command) < 200 else command[:200] + "..."
            error_parts.append(f"COMMAND:\n{cmd_display}")

            msg = "\n".join(error_parts)
            raise RuntimeError(msg)

        return stdout


    def get_session_id(self, username: str) -> Tuple[str, str]:
        """
        Get the Windows session ID for a specific user.

        Args:
            username: Username to search for

        Returns:
            Tuple of (session_id, session_state)

        Raises:
            RuntimeError: If no session found for the user
        """
        # Use PowerShell to run query session and ignore exit code issues
        cmd = "query session"
        try:
            stdout = self.execute_command(cmd, is_ps=False)
        except RuntimeError as e:
            # query session sometimes returns exit code 1 even on success
            # Extract stdout from error message if available
            error_msg = str(e)
            if "STDOUT:" in error_msg:
                # Parse stdout from error message
                stdout_start = error_msg.find("STDOUT:") + 7
                stdout_end = error_msg.find("STDERR:", stdout_start)
                if stdout_end == -1:
                    stdout_end = error_msg.find("COMMAND:", stdout_start)
                stdout = error_msg[stdout_start:stdout_end].strip()
                log.debug(f"Extracted stdout from error: {stdout}")
            else:
                raise

        log.debug(f"Query session output:\n{stdout}")

        # Parse the output to find the user's session
        lines = stdout.strip().split('\n')

        # Extract username without domain (if domain\username format)
        search_username = username.split('\\')[-1] if '\\' in username else username
        log.debug(f"Searching for session with username: {search_username}")

        for line in lines:
            # Look for lines containing the username and state (Active, Disc, Conn, etc.)
            if search_username.lower() in line.lower():
                # Extract session ID and state using regex
                # Format examples:
                # >rdp-tcp#97        Administrator             1  Active
                #  rdp-tcp#97        Administrator             1  Disc
                # Match any number followed by a state
                match = re.search(r'\s+(\d+)\s+(Active|Disc|Conn|Listen|Idle)', line, re.IGNORECASE)
                if match:
                    session_id = match.group(1)
                    session_state = match.group(2)
                    log.info(f"Found session for {username}: ID={session_id}, State={session_state}")
                    return session_id, session_state

        raise RuntimeError(f"No session found for user '{username}'.\nQuery output:\n{stdout}")

    def attach_disconnected_session(self, session_id: str, session_state: str, psexec_path: str):
        """
        Attach a disconnected session to console using PsExec.

        Args:
            session_id: Windows session ID
            session_state: Current session state
            psexec_path: Full path to PsExec.exe (e.g., 'C:\\PSTools\\PsExec.exe')
        """
        if session_state.lower() == 'disc':
            log.info(f"Attaching disconnected session {session_id} to console")

            # Use PowerShell's call operator (&) which handles paths better through WinRM
            # The & operator allows running executables with arguments
            cmd = f"& '{psexec_path}' -accepteula -s cmd /c 'tscon {session_id} /dest:console'"
            self.execute_command(cmd, is_ps=True)

            # Pause for desktop to settle
            log.info("Pausing 10 seconds for desktop to settle")
            time.sleep(10)
        else:
            log.info(f"Session {session_id} is in state '{session_state}', no need to attach")

    # =========================================================================
    # File Operations
    # =========================================================================

    def check_file_exists(self, file_path: str) -> bool:
        """
        Check if a file exists on the remote Windows machine.

        Args:
            file_path: Path to check on remote machine

        Returns:
            True if file exists, False otherwise
        """
        try:
            result = self.execute_command(f"Test-Path '{file_path}'")
            return result.strip().lower() == 'true'
        except Exception:
            return False

    def copy_file_to_remote(self, local_path: str, remote_path: str):
        """
        Copy a file to the remote Windows machine using pypsrp's native file transfer.

        Args:
            local_path: Local file path to copy
            remote_path: Remote destination path on Windows machine

        Raises:
            FileNotFoundError: If local file doesn't exist
            RuntimeError: If file transfer fails
        """
        from lib.passthrough import utils as passthrough_utils
        passthrough_utils.copy_file_to_remote(self, local_path, remote_path)

    def create_directory(self, path: str):
        """
        Create a directory on the remote Windows machine if it doesn't exist.

        Args:
            path: Directory path to create on the remote machine
        """
        path = path.replace('/', '\\')
        cmd = f"New-Item -Path '{path}' -ItemType Directory -Force | Out-Null"
        self.execute_command(cmd)
        log.info(f"Created directory: {path}")

    def remove_file(self, path: str):
        """
        Remove a file from the remote Windows machine if it exists.

        Args:
            path: File path to remove on the remote machine
        """
        path = path.replace('/', '\\')

        check_cmd = f"Test-Path -Path '{path}'"
        try:
            result = self.execute_command(check_cmd).strip().lower()
            if result == 'true':
                cmd = f"Remove-Item -Path '{path}' -Force"
                self.execute_command(cmd)
                log.info(f"Removed file: {path}")
            else:
                log.debug(f"File does not exist (no removal needed): {path}")
        except RuntimeError as e:
            log.debug(f"File removal skipped (error: {e}): {path}")

    def download_file(self, url: str, destination: str):
        """
        Download a file from URL to the remote Windows machine.

        Args:
            url: URL to download from
            destination: Destination path on remote machine

        Raises:
            RuntimeError: If download fails
        """
        log.info(f"Downloading from: {url}")
        cmd = f"$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '{url}' -OutFile '{destination}' -UseBasicParsing"
        try:
            self.execute_command(cmd)
            log.info(f"[OK] Downloaded to: {destination}")
        except Exception as e:
            raise RuntimeError(f"Failed to download from {url}: {e}")

    def extract_zip(self, zip_path: str, destination: str):
        """
        Extract a zip file on the remote Windows machine.

        Args:
            zip_path: Path to zip file on remote machine
            destination: Destination directory on remote machine

        Raises:
            RuntimeError: If extraction fails
        """
        log.info(f"Extracting {zip_path}...")
        cmd = f"$ProgressPreference = 'SilentlyContinue'; Expand-Archive -Path '{zip_path}' -DestinationPath '{destination}' -Force"
        try:
            self.execute_command(cmd)
            log.info(f"[OK] Extracted to: {destination}")
        except Exception as e:
            raise RuntimeError(f"Failed to extract {zip_path}: {e}")

    def cleanup_file(self, file_path: str):
        """
        Remove a file from the remote Windows machine (best effort).

        Args:
            file_path: Path to file to remove
        """
        try:
            self.remove_file(file_path)
            log.info(f"[OK] Cleaned up: {file_path}")
        except Exception as e:
            log.warning(f"Could not clean up {file_path}: {e}")

    def read_log_file(self, log_path: str) -> str:
        """
        Read and return the content of a log file from remote Windows machine.

        Args:
            log_path: Path to the log file on remote machine

        Returns:
            Log file content

        Raises:
            RuntimeError: If log file cannot be read
        """
        log_path = log_path.replace('/', '\\')
        cmd = f"Get-Content '{log_path}'"
        return self.execute_command(cmd)

    def wait_for_log_completion(self, log_path: str, completion_marker: str = 'Script Execution Completed',
                                timeout: int = 500, interval: int = 5) -> bool:
        """
        Wait for the script execution to complete by monitoring the log file.

        Args:
            log_path: Path to the log file on remote machine
            completion_marker: The marker string that indicates successful completion
            timeout: Maximum time to wait in seconds
            interval: Check interval in seconds

        Returns:
            True if completion marker found, False if timeout
        """
        start_time = time.time()
        max_retries = timeout // interval

        log.info(f"Waiting for script completion (max {timeout}s)...")

        for attempt in range(max_retries):
            try:
                content = self.read_log_file(log_path)
                if completion_marker in content:
                    log.info("Script execution completed successfully")
                    return True
            except RuntimeError:
                pass  # Log file might not exist yet

            elapsed = time.time() - start_time
            log.debug(f"Attempt {attempt + 1}/{max_retries}: Completion marker not found yet (elapsed: {elapsed:.1f}s)")
            time.sleep(interval)

        log.error(f"Timeout waiting for script completion after {timeout}s")
        return False

    # =========================================================================
    # LAN Profile Management
    # =========================================================================

    def delete_lan_profile(self, nicname: str):
        """
        Delete existing LAN profile from the specified network interface.

        Args:
            nicname: Network interface name (e.g., 'pciPassthru0')
        """
        log.info(f"Deleting LAN profile from interface: {nicname}")

        cmd = f'netsh lan delete profile interface="{nicname}"'
        try:
            result = self.execute_command(cmd, is_ps=False)
            log.info(f"[OK] LAN profile deleted from {nicname}")
        except RuntimeError as e:
            # Profile might not exist, which is okay
            if "is not configured" in str(e) or "not found" in str(e).lower():
                log.info("No existing LAN profile found - continuing")
            else:
                raise

    def add_lan_profile(self, profile_path: str, nicname: str):
        """
        Add a new LAN profile to the specified network interface.

        Args:
            profile_path: Full path to the XML profile on remote machine
            nicname: Network interface name (e.g., 'pciPassthru0')

        Raises:
            AssertionError: If profile addition fails
        """
        log.info(f"Adding LAN profile to interface: {nicname}")

        cmd = f'netsh lan add profile filename="{profile_path}" interface="{nicname}"'
        result = self.execute_command(cmd, is_ps=False)

        expected_message = f"The profile was added successfully on the interface {nicname}."
        if expected_message not in result:
            raise AssertionError(f"LAN profile addition failed. Expected: '{expected_message}', Got: '{result}'")

        log.info(f"[OK] LAN profile added to {nicname}")

    # =========================================================================
    # NIC Management
    # =========================================================================

    def disable_nic(self, nicname: str, timeout: int = 30):
        """
        Disable a network interface.

        Args:
            nicname: Network interface name (e.g., 'pciPassthru0')
            timeout: Maximum time to wait for NIC to be disabled
        """
        log.info(f"Disabling NIC: {nicname}")

        cmd = f"Disable-NetAdapter -Name '{nicname}' -Confirm:$false"
        self.execute_command(cmd)

        self._wait_for_nic_status(nicname, "Disabled", timeout)
        log.info(f"[OK] NIC {nicname} is disabled")

    def enable_nic(self, nicname: str, timeout: int = 30):
        """
        Enable a network interface.

        Args:
            nicname: Network interface name (e.g., 'pciPassthru0')
            timeout: Maximum time to wait for NIC to be enabled
        """
        log.info(f"Enabling NIC: {nicname}")

        cmd = f"Enable-NetAdapter -Name '{nicname}' -Confirm:$false"
        self.execute_command(cmd)

        self._wait_for_nic_status(nicname, "Up", timeout)
        log.info(f"[OK] NIC {nicname} is enabled")

    def toggle_nic(self, nicname: str, timeout: int = 30):
        """
        Toggle (disable then enable) a network interface to trigger re-authentication.

        Args:
            nicname: Network interface name (e.g., 'pciPassthru0')
            timeout: Maximum time to wait for each operation
        """
        log.info(f"Toggling NIC: {nicname}")
        self.disable_nic(nicname, timeout)
        self.enable_nic(nicname, timeout)
        log.info(f"[OK] NIC {nicname} toggled successfully")

    def _wait_for_nic_status(self, nicname: str, expected_status: str, timeout: int = 30, interval: int = 2):
        """
        Wait for a NIC to reach the expected status.

        Args:
            nicname: Network interface name
            expected_status: Expected status ('Up', 'Disabled', etc.)
            timeout: Maximum time to wait in seconds
            interval: Interval in seconds between status checks

        Raises:
            AssertionError: If NIC doesn't reach expected status within timeout
        """
        log.info(f"Waiting for NIC '{nicname}' to reach '{expected_status}' status (max {timeout}s)...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                status = self.get_nic_status(nicname)
                if expected_status in status:
                    log.info(f"[OK] NIC '{nicname}' status: '{status}'")
                    return
                log.debug(f"NIC {nicname} status: {status}, waiting for: {expected_status}")
            except RuntimeError as e:
                log.debug(f"Error checking NIC status: {e}")

            time.sleep(interval)

        raise AssertionError(f"NIC {nicname} did not reach status '{expected_status}' within {timeout}s")

    def get_nic_status(self, nicname: str) -> str:
        """
        Get the current status of a network interface.

        Args:
            nicname: Network interface name (e.g., 'pciPassthru0')

        Returns:
            NIC status string

        Raises:
            RuntimeError: If unable to get NIC status
        """
        cmd = f'(Get-NetAdapter -Name "{nicname}" -ErrorAction SilentlyContinue).Status'
        return self.execute_command(cmd).strip()

    def get_nic_ip(self, nicname: str) -> Optional[str]:
        """
        Get the IPv4 address of a network interface.

        Args:
            nicname: Network interface name (e.g., 'Ethernet')

        Returns:
            IPv4 address as string, or None if no IP assigned
        """
        cmd = f'(Get-NetIPAddress -InterfaceAlias "{nicname}" -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress'
        try:
            result = self.execute_command(cmd).strip()
            if result and result != "":
                log.debug(f"NIC '{nicname}' IP address: {result}")
                return result
        except RuntimeError:
            pass
        return None

    def is_ip_in_range(self, ip: str, ip_range: str) -> bool:
        """
        Check if an IP address is within a CIDR range.

        Args:
            ip: IP address to check (e.g., '10.16.148.130')
            ip_range: CIDR range (e.g., '10.16.148.128/26')

        Returns:
            True if IP is in range, False otherwise
        """
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return ipaddress.ip_address(ip) in network
        except ValueError as e:
            log.warning(f"Invalid IP or range: {e}")
            return False

    def wait_for_nic_ip_in_range(self, nicname: str, ip_range: str, timeout: int = 90, interval: int = 5) -> str:
        """
        Wait for NIC to get an IP address within the specified CIDR range.

        Args:
            nicname: Network interface name (e.g., 'Ethernet')
            ip_range: Target CIDR range (e.g., '10.16.148.128/26')
            timeout: Maximum time to wait in seconds (default: 90)
            interval: Interval in seconds between checks (default: 5)

        Returns:
            The IP address that was assigned

        Raises:
            AssertionError: If NIC does not get an IP in range within timeout
        """
        log.info(f"Waiting for NIC '{nicname}' to get IP in range '{ip_range}' (max {timeout}s)...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            current_ip = self.get_nic_ip(nicname)
            if current_ip:
                if self.is_ip_in_range(current_ip, ip_range):
                    log.info(f"[OK] NIC '{nicname}' got IP '{current_ip}' which is in range '{ip_range}'")
                    return current_ip
                else:
                    log.debug(f"NIC '{nicname}' has IP '{current_ip}' but not in target range '{ip_range}'")
            else:
                log.debug(f"NIC '{nicname}' has no IP yet")

            time.sleep(interval)

        current_ip = self.get_nic_ip(nicname)
        raise AssertionError(
            f"NIC '{nicname}' did not get IP in range '{ip_range}' within {timeout}s. Current IP: {current_ip}"
        )

    def get_nic_authentication_status(self, nicname: str) -> str:
        """
        Get the 802.1X authentication status of a network interface using netsh.

        Args:
            nicname: Network interface name (e.g., 'pciPassthru0')

        Returns:
            Output of netsh lan show interfaces command

        Raises:
            RuntimeError: If unable to get authentication status
        """
        cmd = f'netsh lan show interfaces interface="{nicname}"'
        return self.execute_command(cmd, is_ps=False)

    def wait_for_nic_authentication(self, nicname: str,
                                     expected_status: Union[AuthenticationStatus, str] = AuthenticationStatus.SUCCEEDED,
                                     timeout: int = 90, interval: int = 5):
        """
        Wait for NIC to reach expected 802.1X authentication status.

        Args:
            nicname: Network interface name (e.g., 'pciPassthru0')
            expected_status: Expected authentication status (default: AuthenticationStatus.SUCCEEDED)
            timeout: Maximum time to wait in seconds (default: 90)
            interval: Interval in seconds between status checks (default: 5)

        Raises:
            AssertionError: If NIC does not reach expected status within timeout
        """
        # Convert enum to string value if needed
        status_value = expected_status.value if isinstance(expected_status, AuthenticationStatus) else expected_status

        log.info(f"Waiting for NIC '{nicname}' 802.1X authentication (max {timeout}s)...")
        start_time = time.time()
        last_status = None

        while time.time() - start_time < timeout:
            try:
                output = self.get_nic_authentication_status(nicname)
                last_status = output
                if status_value in output:
                    log.info(f"[OK] NIC '{nicname}' authentication status: '{status_value}'")
                    return
                log.debug(f"NIC {nicname} auth status not ready, waiting for: {status_value}")
            except RuntimeError as e:
                log.debug(f"Error checking NIC authentication status: {e}")

            time.sleep(interval)

        raise AssertionError(
            f"NIC '{nicname}' did not reach authentication status '{status_value}' within {timeout}s. "
            f"Actual status: '{last_status}'"
        )

    # =========================================================================
    # Tool Management
    # =========================================================================

    def download_psexec(self, pstools_path: str, psexec_path: str):
        """
        Download and extract PsExec on the remote Windows machine if not already present.

        Args:
            pstools_path: Path to PSTools directory (e.g., 'C:\\PSTools')
            psexec_path: Full path to PsExec.exe (e.g., 'C:\\PSTools\\PsExec.exe')

        Raises:
            RuntimeError: If download or extraction fails
        """
        PSTOOLS_URL = "https://download.sysinternals.com/files/PSTools.zip"

        log.info("=== Checking/Downloading PsExec ===")

        if self.check_file_exists(psexec_path):
            log.info(f"[OK] PsExec already exists at: {psexec_path}")
            return

        log.info("PsExec not found, downloading from Microsoft Sysinternals...")

        zip_path = f"{pstools_path}\\PSTools.zip"

        self.create_directory(pstools_path)
        self.download_file(PSTOOLS_URL, zip_path)
        self.extract_zip(zip_path, pstools_path)

        if not self.check_file_exists(psexec_path):
            raise RuntimeError(f"PsExec.exe not found after extraction at: {psexec_path}")

        log.info(f"[OK] PsExec is ready at: {psexec_path}")
        self.cleanup_file(zip_path)

