from framework.log.logger import log
from lib.passthrough.passthrough_base import PassthroughBase
from lib.passthrough.enums import AuthenticationStatus
import ipaddress
import winrm
import re
import time
from typing import Optional, Tuple, Union


class WindowsPassthrough(PassthroughBase):

    # Registry base path for Schannel protocol version controls and winlogon
    _REG_SCHANNEL = r'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    _REG_WINLOGON = r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    # Marker file written after each TLS version change so we can skip redundant reboots
    _TLS_MARKER_PATH = r'C:\Windows\Temp\fstester_tls_version.txt'

    def __init__(self, ip: str, user_name: str, password: str, mac: str, nicname: str = "pciPassthru0"):
        super().__init__(ip, user_name, password, mac, nicname)
        self.win_con = winrm.Session(self.ip, auth=(self.username, self.password), transport='ntlm')
        self._reboot_initiated_at: Optional[float] = None
        self._auto_logon_configured: bool = False
        self._reboot_for_tls: bool = False
        self._reboot_for_auto_logon: bool = False

    def _new_session(self) -> winrm.Session:
        """Create and return a fresh WinRM session."""
        return winrm.Session(self.ip, auth=(self.username, self.password), transport='ntlm')

    def trigger_reboot(self):
        """Trigger a Windows reboot without waiting.  The next ``execute_command``
        call will automatically wait for the machine to come back."""
        try:
            self.execute_command("Restart-Computer -Force")
        except Exception as e:
            log.debug(f"WinRM disconnected (expected during reboot): {e!r}")
        self._reboot_initiated_at = time.time()
        # Once a reboot is scheduled the pending-flags should be cleared so
        # subsequent calls to need_reboot() don't spuriously return True.
        self._reboot_for_tls = False
        self._reboot_for_auto_logon = False
        log.info("[reboot] Initiated — will wait lazily on next WinRM call")

    def _wait_if_reboot_pending(self):
        """If a reboot was triggered, block until Windows is back online.
        The 30 s initial-wait is reduced by however much time has already
        elapsed (e.g. while the framework configured CA / switch)."""
        if self._reboot_initiated_at is None:
            return
        elapsed = time.time() - self._reboot_initiated_at
        remaining_initial = max(0, 30 - elapsed)
        self._reboot_initiated_at = None          # clear BEFORE waiting (avoids recursion)
        log.info(f"[reboot] {elapsed:.0f}s since reboot was triggered, "
                 f"initial_wait reduced to {remaining_initial:.0f}s")
        self.wait_for_windows_reboot(initial_wait=int(remaining_initial))

    def execute_command(self, command, is_ps=True):
        # For PowerShell commands, suppress progress output to avoid CLIXML errors
        self._wait_if_reboot_pending()
        if is_ps and "$ProgressPreference" not in command:
            command = f"$ProgressPreference = 'SilentlyContinue'; {command}"

        log.info(f"Executing command on WindowsPassthrough: {command}")

        for attempt in range(2):
            try:
                out = self.win_con.run_ps(command) if is_ps else self.win_con.run_cmd(command)
                break
            except Exception as e:
                if attempt == 0:
                    log.warning(
                        f"WinRM transport error on attempt {attempt + 1} "
                        f"(session may have dropped), reconnecting: {e!r}"
                    )
                    self.win_con = self._new_session()
                else:
                    raise RuntimeError(f"Failed to execute command '{command}': {e}") from e

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

        self._wait_for_nic_media_state(nicname, "Connected", timeout)
        log.info(f"[OK] NIC {nicname} is connected")

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

    def _wait_for_nic_media_state(self, nicname: str, expected_state: str, timeout: int = 30, interval: int = 2):
        """
        Wait for a NIC to reach the expected MediaConnectionState.

        Args:
            nicname: Network interface name
            expected_state: Expected media state (e.g., 'Connected')
            timeout: Maximum time to wait in seconds
            interval: Interval in seconds between checks

        Raises:
            AssertionError: If NIC doesn't reach expected state within timeout
        """
        log.info(f"Waiting for NIC '{nicname}' MediaConnectionState '{expected_state}' (max {timeout}s)...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                cmd = f'(Get-NetAdapter -Name "{nicname}").MediaConnectionState'
                state = self.execute_command(cmd).strip()
                if expected_state in state:
                    log.info(f"[OK] NIC '{nicname}' MediaConnectionState: '{state}'")
                    return
                log.debug(f"NIC {nicname} MediaConnectionState: {state}, waiting for: {expected_state}")
            except RuntimeError as e:
                log.debug(f"Error checking NIC MediaConnectionState: {e}")

            time.sleep(interval)

        raise AssertionError(
            f"NIC {nicname} did not reach MediaConnectionState '{expected_state}' within {timeout}s"
        )

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

    def get_nic_mac_address(self, nicname: str = None) -> str:
        """
        Get the MAC address of a network interface.

        Args:
            nicname: Network interface name (e.g., 'pciPassthru0').
                    If None, uses self.nicname.

        Returns:
            MAC address as string (e.g., '98-F2-B3-01-A0-55')

        Raises:
            RuntimeError: If unable to get MAC address
        """
        if nicname is None:
            nicname = self.nicname
        cmd = f'(Get-NetAdapter -Name "{nicname}" -ErrorAction Stop).MacAddress'
        result = self.execute_command(cmd).strip()
        log.info(f"NIC '{nicname}' MAC address: {result}")
        return result

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

    # =========================================================================
    # Windows Auto-Logon
    # =========================================================================

    def ensure_auto_logon(self, reboot: bool = False):
        """
        Configure Windows to automatically log in as the WinRM user after every
        reboot or logout.  This is required for UI-automation scripts (PsExec -i)
        to find an active desktop session.
        """
        # If we've already configured auto-logon earlier in this process,
        # avoid re-checking/writing the registry (prevents duplicate reboots)
        if getattr(self, '_auto_logon_configured', False):
            log.info(f"[auto-logon] Already configured in this run for '{self.username}', skipping")
            return

        desired = {
            'AutoAdminLogon': '1',
            'DefaultUserName': self.username,
            'DefaultPassword': self.password,
        }
        # Force PowerShell to return simple Key:Value lines (no table formatting)
        get_cmd = (
            f"$p = Get-ItemProperty -Path '{self._REG_WINLOGON}' -ErrorAction SilentlyContinue; "
            "Write-Output \"AutoAdminLogon:$($p.AutoAdminLogon)\"; "
            "Write-Output \"DefaultUserName:$($p.DefaultUserName)\"; "
            "Write-Output \"DefaultPassword:$($p.DefaultPassword)\""
        )

        current = {}
        try:
            raw = self.execute_command(get_cmd)
        except RuntimeError as e:
            log.debug(f"Unable to read auto-logon keys: {e}")
            raw = ''

        # Parse Key:Value lines produced above
        for line in raw.splitlines():
            if ':' not in line:
                continue
            key, val = line.split(':', 1)
            current[key.strip()] = val.strip()

        to_change = []
        for key, expected in desired.items():
            actual = current.get(key)
            if actual != expected:
                to_change.append(key)

        if not to_change:
            log.info(f"[auto-logon] Keys already match for '{self.username}', skipping reboot")
            # Mark as configured so subsequent setups in the same run don't rewrite
            self._auto_logon_configured = True
            # No reboot required because nothing changed
            self._reboot_for_auto_logon = False
            return

        set_cmds = []
        for key in to_change:
            value = desired[key]
            set_cmds.append(
                f"Set-ItemProperty -Path '{self._REG_WINLOGON}' -Name '{key}' -Value '{value}'"
            )

        self.execute_command('; '.join(set_cmds))
        # mark configured BEFORE reboot so later calls won't reapply while WinRM settles
        self._auto_logon_configured = True
        # Changes to Winlogon require a reboot to take full effect
        self._reboot_for_auto_logon = True
        log.info(f"[auto-logon] Configured auto-logon for user '{self.username}' because {', '.join(to_change)} differed")
        if reboot and self._reboot_for_auto_logon:
            log.info("[auto-logon] triggering reboot to apply changes...")
            self.trigger_reboot()

    def restore_auto_logon_defaults(self, reboot: bool = False):
        """
        Restore Winlogon auto-logon settings to defaults by removing the
        keys set by `ensure_auto_logon`. Optionally triggers a reboot so
        changes take effect.

        Args:
            reboot: If True, trigger a non-blocking reboot after removing
                    the registry properties. Defaults to False.
        """
        log.info("=== Restoring Winlogon auto-logon defaults ===")
        lines = [
            # Remove keys we set earlier; SilentlyContinue avoids noisy errors
            f"Remove-ItemProperty -Path '{self._REG_WINLOGON}' -Name 'AutoAdminLogon','DefaultUserName','DefaultPassword' -ErrorAction SilentlyContinue",
        ]

        try:
            self.execute_command('; '.join(lines))
            # Clear in-memory flag so future runs may reapply if needed
            self._auto_logon_configured = False
            log.info("[auto-logon] Winlogon properties removed (or already absent)")
        except RuntimeError as e:
            log.warning(f"Failed to remove Winlogon properties: {e}")
        if reboot:
            log.info("[Restore auto-logon] triggering reboot to apply changes...")
            self.trigger_reboot()    

    # =========================================================================
    # Windows TLS Version Management
    # =========================================================================

    def get_windows_tls_version(self) -> str:
        """
        Return the TLS version last set by fstester (e.g. '1.0', '1.1'),
        or 'default' if the marker file has never been written.
        """
        marker = self._TLS_MARKER_PATH
        cmd = (
            f"if (Test-Path '{marker}') "
            f"{{ (Get-Content '{marker}').Trim() }} "
            f"else {{ 'default' }}"
        )
        return self.execute_command(cmd).strip()

    def set_windows_tls_only(self, version: str):
        """
        Restrict Windows Schannel so the endpoint negotiates *only* the
        specified TLS version.  All other client-side TLS versions (1.0–1.2)
        are explicitly disabled.  Writes a marker file and marks the
        endpoint for reboot (non-blocking). This method does NOT itself
        trigger the reboot — callers should call :py:meth:`trigger_reboot`
        or use :py:meth:`ensure_windows_tls_version` with ``reboot=True``
        to actually perform the reboot. The next ``execute_command`` call
        will wait for the machine to come back if a reboot was triggered.

        Args:
            version: '1.0', '1.1', or '1.2'

        Raises:
            ValueError: For unsupported version strings.
        """
        if version not in {'1.0', '1.1', '1.2'}:
            raise ValueError(f"Unsupported TLS version '{version}'. Supported: '1.0', '1.1', '1.2'")

        log.info(f"=== Restricting Windows Schannel to TLS {version} only (will reboot) ===")
        marker = self._TLS_MARKER_PATH
        base = self._REG_SCHANNEL

        lines: list[str] = []
        for ver in ['1.0', '1.1', '1.2']:
            key = f"{base}\\TLS {ver}\\Client"
            enabled = 1 if ver == version else 0
            disabled_default = 0 if ver == version else 1
            lines += [
                f"New-Item -Path '{key}' -Force | Out-Null",
                f"Set-ItemProperty -Path '{key}' -Name 'Enabled' -Value {enabled} -Type DWord",
                f"Set-ItemProperty -Path '{key}' -Name 'DisabledByDefault' -Value {disabled_default} -Type DWord",
            ]

        tls12_server = f"{base}\\TLS 1.2\\Server"
        lines += [
            f"New-Item -Path '{tls12_server}' -Force | Out-Null",
            f"Set-ItemProperty -Path '{tls12_server}' -Name 'Enabled' -Value 1 -Type DWord",
            f"Set-ItemProperty -Path '{tls12_server}' -Name 'DisabledByDefault' -Value 0 -Type DWord",
        ]
        lines.append(f"Set-Content -Path '{marker}' -Value '{version}'")

        self.execute_command('; '.join(lines))
        # TLS registry changes require a reboot to take effect
        self._reboot_for_tls = True
        log.info(f"Registry set for TLS {version} (reboot flagged but not triggered)")

    def ensure_windows_tls_version(self, version: str, reboot: bool = False):
        """
        Idempotent wrapper: set Windows TLS to *version* only if it is not
        already set to that version.  Avoids an unnecessary reboot when
        consecutive test classes share the same TLS requirement.

        Args:
            version: '1.0', '1.1', or '1.2'
        """
        current = self.get_windows_tls_version()
        if current == version:
            log.info(f"[TLS] Windows already restricted to TLS {version} — skipping reboot")
            # Nothing to change so ensure the reboot flag is cleared.
            self._reboot_for_tls = False
            return
        log.info(f"[TLS] Current marker='{current}', changing to TLS {version}")
        self.set_windows_tls_only(version)
        if reboot and self._reboot_for_tls:
            log.info("[TLS] Triggering reboot to apply TLS changes...")
            self.trigger_reboot()

    def restore_windows_tls_defaults(self):
        """
        Remove all TLS registry keys added by fstester, restoring Windows
        Schannel to OS defaults (all TLS versions enabled implicitly).
        Deletes the marker file then reboots.
        """
        log.info("=== Restoring Windows Schannel TLS defaults (removing TLS keys) ===")
        marker = self._TLS_MARKER_PATH
        base = self._REG_SCHANNEL

        lines: list[str] = []
        # Remove the entire TLS {ver} key (including any Client/Server subkeys)
        # so no TLS 1.x folders remain. Use -Recurse -Force and SilentlyContinue
        # to be best-effort and quiet when keys are absent.
        for ver in ['1.0', '1.1', '1.2']:
            tls_key = f"{base}\\TLS {ver}"
            lines.append(f"Remove-Item -Path '{tls_key}' -Recurse -Force -ErrorAction SilentlyContinue")
        # Remove marker file if present
        lines.append(f"Remove-Item -Path '{marker}' -Force -ErrorAction SilentlyContinue")

        self.execute_command('; '.join(lines))
        log.info("TLS keys removed, rebooting...")
        self.trigger_reboot()
        self.wait_for_windows_reboot()

    def wait_for_windows_reboot(self, timeout: int = 420, initial_wait: int = 30):
        """
        Wait for Windows to finish rebooting and become reachable via WinRM.

        Args:
            timeout:      Maximum seconds to poll after *initial_wait* (default 300).
            initial_wait: Seconds to sleep before polling starts (default 30),
                          giving the machine time to actually start the shutdown.

        Raises:
            RuntimeError: If the machine does not come back within the wait window.
        """
        log.info(f"Waiting {initial_wait}s for Windows to begin rebooting...")
        time.sleep(initial_wait)

        start = time.time()
        log.info(f"Polling for WinRM availability (max {timeout}s)...")
        while time.time() - start < timeout:
            try:
                self.win_con = self._new_session()
                result = self.execute_command("Write-Output 'alive'").strip()
                if 'alive' in result:
                    log.info("[OK] Windows is back online after reboot — settling 15s...")
                    time.sleep(15)
                    # Clear any pending reboot flags now that the system is back.
                    self._reboot_for_tls = False
                    self._reboot_for_auto_logon = False
                    return
            except Exception as e:
                log.debug(f"Windows not yet reachable: {e!r}")
            time.sleep(10)

        raise RuntimeError(
            f"Windows did not come back online within {initial_wait + timeout}s after reboot"
        )

    def need_reboot(self) -> bool:
        """Return True if any recent configuration requires a reboot to take effect.

        This is a convenience used by test mixins to decide whether to trigger
        a reboot after making changes (TLS or auto-logon).
        """
        return bool(getattr(self, '_reboot_for_tls', False) or getattr(self, '_reboot_for_auto_logon', False))
