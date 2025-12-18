from framework.log.logger import log
from lib.passthrough.passthrough_base import PassthroughBase
import winrm
import re
import time
from typing import Tuple


class WindowsPassthrough(PassthroughBase):
    def __init__(self, ip: str, user_name: str, password: str, mac: str):
        super().__init__(ip, user_name, password, mac)
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

    def _wait_for_nic_status(self, nicname: str, expected_status: str, timeout: int = 30):
        """
        Wait for a NIC to reach the expected status.

        Args:
            nicname: Network interface name
            expected_status: Expected status ('Up', 'Disabled', etc.)
            timeout: Maximum time to wait in seconds

        Raises:
            AssertionError: If NIC doesn't reach expected status within timeout
        """
        start_time = time.time()
        interval = 2

        while time.time() - start_time < timeout:
            cmd = f"(Get-NetAdapter -Name '{nicname}').Status"
            try:
                status = self.execute_command(cmd).strip()
                if status == expected_status:
                    return
                log.debug(f"NIC {nicname} status: {status}, waiting for: {expected_status}")
            except RuntimeError as e:
                log.debug(f"Error checking NIC status: {e}")

            time.sleep(interval)

        raise AssertionError(f"NIC {nicname} did not reach status '{expected_status}' within {timeout}s")

