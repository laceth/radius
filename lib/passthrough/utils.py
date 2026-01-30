"""
Utility functions for passthrough operations.
"""
import os
from framework.log.logger import log


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


def copy_file_to_remote(passthrough, local_path: str, remote_path: str):
    """
    Copy a file to a remote machine using pypsrp's native file transfer.

    Args:
        passthrough: Passthrough instance with ip, username, password attributes
        local_path: Local file path to copy
        remote_path: Remote destination path

    Raises:
        FileNotFoundError: If local file doesn't exist
        RuntimeError: If file transfer fails
    """
    from pypsrp.client import Client

    if not os.path.exists(local_path):
        raise FileNotFoundError(f"Local file not found: {local_path}")

    log.info(f"Copying {local_path} to {remote_path}")

    remote_path = remote_path.replace('/', '\\')
    remote_dir = remote_path.rsplit('\\', 1)[0]

    file_size = os.path.getsize(local_path)
    log.info(f"File size: {file_size} bytes")

    # Create directory if passthrough supports it
    if hasattr(passthrough, 'create_directory'):
        passthrough.create_directory(remote_dir)

    try:
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

