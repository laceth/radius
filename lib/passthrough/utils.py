"""
Utility functions for Windows passthrough operations.
"""
from framework.log.logger import log


def check_file_exists(passthrough, file_path: str) -> bool:
    """
    Check if a file exists on the remote Windows machine.

    Args:
        passthrough: WindowsPassthrough instance
        file_path: Path to check on remote machine

    Returns:
        True if file exists, False otherwise
    """
    try:
        result = passthrough.execute_command(f"Test-Path '{file_path}'")
        return result.strip().lower() == 'true'
    except Exception:
        return False


def download_file(passthrough, url: str, destination: str):
    """
    Download a file from URL to the remote Windows machine.

    Args:
        passthrough: WindowsPassthrough instance
        url: URL to download from
        destination: Destination path on remote machine

    Raises:
        RuntimeError: If download fails
    """
    log.info(f"Downloading from: {url}")
    cmd = f"$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '{url}' -OutFile '{destination}' -UseBasicParsing"
    try:
        passthrough.execute_command(cmd)
        log.info(f"[OK] Downloaded to: {destination}")
    except Exception as e:
        raise RuntimeError(f"Failed to download from {url}: {e}")


def copy_file_to_remote(passthrough, local_path: str, remote_path: str):
    """
    Copy a file to the remote Windows machine using pypsrp's native file transfer.

    Args:
        passthrough: WindowsPassthrough instance
        local_path: Local file path to copy
        remote_path: Remote destination path on Windows machine

    Raises:
        FileNotFoundError: If local file doesn't exist
        RuntimeError: If file transfer fails
    """
    import os
    from pypsrp.client import Client

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
    create_directory(passthrough, remote_dir)

    try:
        # Use pypsrp's efficient native file transfer
        log.info("Using pypsrp native file transfer")
        client = Client(
            passthrough.ip,
            username=passthrough.username,
            password=passthrough.password,
            ssl=False,
            auth="ntlm"
        )
        client.copy(local_path, remote_path)
        log.info(f"Successfully copied {local_path} to {remote_path}")

    except Exception as e:
        log.error(f"Failed to copy file: {e}")
        raise RuntimeError(f"File transfer failed: {e}")


def create_directory(passthrough, path: str):
    """
    Create a directory on the remote Windows machine if it doesn't exist.

    Args:
        passthrough: WindowsPassthrough instance
        path: Directory path to create on the remote machine
    """
    path = path.replace('/', '\\')
    cmd = f"New-Item -Path '{path}' -ItemType Directory -Force | Out-Null"
    passthrough.execute_command(cmd)
    log.info(f"Created directory: {path}")


def remove_file(passthrough, path: str):
    """
    Remove a file from the remote Windows machine if it exists.

    Args:
        passthrough: WindowsPassthrough instance
        path: File path to remove on the remote machine
    """
    path = path.replace('/', '\\')

    # First check if file exists to avoid unnecessary errors
    check_cmd = f"Test-Path -Path '{path}'"
    try:
        result = passthrough.execute_command(check_cmd).strip().lower()
        if result == 'true':
            # File exists, remove it
            cmd = f"Remove-Item -Path '{path}' -Force"
            passthrough.execute_command(cmd)
            log.info(f"Removed file: {path}")
        else:
            log.debug(f"File does not exist (no removal needed): {path}")
    except RuntimeError as e:
        # If anything fails, just log and continue (file removal is not critical)
        log.debug(f"File removal skipped (error: {e}): {path}")


def extract_zip(passthrough, zip_path: str, destination: str):
    """
    Extract a zip file on the remote Windows machine.

    Args:
        passthrough: WindowsPassthrough instance
        zip_path: Path to zip file on remote machine
        destination: Destination directory on remote machine

    Raises:
        RuntimeError: If extraction fails
    """
    log.info(f"Extracting {zip_path}...")
    cmd = f"$ProgressPreference = 'SilentlyContinue'; Expand-Archive -Path '{zip_path}' -DestinationPath '{destination}' -Force"
    try:
        passthrough.execute_command(cmd)
        log.info(f"[OK] Extracted to: {destination}")
    except Exception as e:
        raise RuntimeError(f"Failed to extract {zip_path}: {e}")


def cleanup_file(passthrough, file_path: str):
    """
    Remove a file from the remote Windows machine (best effort).

    Args:
        passthrough: WindowsPassthrough instance
        file_path: Path to file to remove
    """
    try:
        passthrough.remove_file(file_path)
        log.info(f"[OK] Cleaned up: {file_path}")
    except Exception as e:
        log.warning(f"Could not clean up {file_path}: {e}")


def verify_log_content(log_content: str, completion_marker: str = 'Script Execution Completed') -> bool:
    """
    Verify the log content contains the expected completion marker.

    Args:
        log_content: The log file content to verify
        completion_marker: The marker string that indicates successful completion

    Returns:
        True if completion marker found

    Raises:
        AssertionError: If completion marker is not found
    """
    log.info(f"Verifying log content for completion marker: '{completion_marker}'")

    if completion_marker not in log_content:
        raise AssertionError(f"Log does not contain '{completion_marker}' marker")

    log.info(f"[OK] Found completion marker: '{completion_marker}'")
    return True


def read_log_file(passthrough, log_path: str) -> str:
    """
    Read and return the content of a log file from remote Windows machine.

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
    return passthrough.execute_command(cmd)


def wait_for_log_completion(passthrough, log_path: str, completion_marker: str = 'Script Execution Completed',
                            timeout: int = 500, interval: int = 5) -> bool:
    """
    Wait for the script execution to complete by monitoring the log file.

    Args:
        passthrough: WindowsPassthrough instance for executing commands
        log_path: Path to the log file on remote machine
        completion_marker: The marker string that indicates successful completion
        timeout: Maximum time to wait in seconds
        interval: Check interval in seconds

    Returns:
        True if completion marker found, False if timeout
    """
    import time

    start_time = time.time()
    max_retries = timeout // interval

    log.info(f"Waiting for script completion (checking every {interval}s, max {timeout}s)")

    for attempt in range(max_retries):
        try:
            content = read_log_file(passthrough, log_path)
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


def download_psexec(passthrough, pstools_path: str, psexec_path: str):
    """
    Download and extract PsExec on the remote Windows machine if not already present.

    Args:
        passthrough: WindowsPassthrough instance for file operations
        pstools_path: Path to PSTools directory (e.g., 'C:\\PSTools')
        psexec_path: Full path to PsExec.exe (e.g., 'C:\\PSTools\\PsExec.exe')

    Raises:
        RuntimeError: If download or extraction fails
    """
    PSTOOLS_URL = "https://download.sysinternals.com/files/PSTools.zip"

    log.info("=== Checking/Downloading PsExec ===")

    if check_file_exists(passthrough, psexec_path):
        log.info(f"[OK] PsExec already exists at: {psexec_path}")
        return

    log.info("PsExec not found, downloading from Microsoft Sysinternals...")

    zip_path = f"{pstools_path}\\PSTools.zip"

    create_directory(passthrough, pstools_path)
    download_file(passthrough, PSTOOLS_URL, zip_path)
    extract_zip(passthrough, zip_path, pstools_path)

    if not check_file_exists(passthrough, psexec_path):
        raise RuntimeError(f"PsExec.exe not found after extraction at: {psexec_path}")

    log.info(f"[OK] PsExec is ready at: {psexec_path}")
    cleanup_file(passthrough, zip_path)



