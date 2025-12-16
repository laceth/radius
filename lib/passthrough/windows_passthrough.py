from framework.log.logger import log
from lib.passthrough.passthrough_base import PassthroughBase
import winrm
import os
import re
import time
from datetime import datetime
from typing import Tuple

from pypsrp.client import Client


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
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Local file not found: {local_path}")

        log.info(f"Copying {local_path} to {remote_path}")

        # Normalize path to Windows format
        remote_path = remote_path.replace('/', '\\')
        remote_dir = remote_path.rsplit('\\', 1)[0]

        # Get file size for logging
        file_size = os.path.getsize(local_path)
        log.info(f"File size: {file_size} bytes")

        # Create directory if it doesn't exist
        self.execute_command(f"New-Item -Path '{remote_dir}' -ItemType Directory -Force | Out-Null")

        try:
            # Use pypsrp's efficient native file transfer
            log.info("Using pypsrp native file transfer")
            client = Client(
                self.ip,
                username=self.username,
                password=self.password,
                ssl=False,
                auth="ntlm"
            )
            client.copy(local_path, remote_path)
            log.info(f"Successfully copied {local_path} to {remote_path}")

        except Exception as e:
            log.error(f"Failed to copy file: {e}")
            raise RuntimeError(f"File transfer failed: {e}")

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

        # First check if file exists to avoid unnecessary errors
        check_cmd = f"Test-Path -Path '{path}'"
        try:
            result = self.execute_command(check_cmd).strip().lower()
            if result == 'true':
                # File exists, remove it
                cmd = f"Remove-Item -Path '{path}' -Force"
                self.execute_command(cmd)
                log.info(f"Removed file: {path}")
            else:
                log.debug(f"File does not exist (no removal needed): {path}")
        except RuntimeError as e:
            # If anything fails, just log and continue (file removal is not critical)
            log.debug(f"File removal skipped (error: {e}): {path}")
            pass

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

    def attach_disconnected_session(self, session_id: str, session_state: str):
        """
        Attach a disconnected session to console.

        Args:
            session_id: Windows session ID
            session_state: Current session state
        """
        if session_state.lower() == 'disc':
            log.info(f"Attaching disconnected session {session_id} to console")
            cmd = f'psexec -accepteula -s cmd /c "tscon {session_id} /dest:console"'
            self.execute_command(cmd, is_ps=False)

            # Pause for desktop to settle
            log.info("Pausing 10 seconds for desktop to settle")
            time.sleep(10)
        else:
            log.info(f"Session {session_id} is in state '{session_state}', no need to attach")

