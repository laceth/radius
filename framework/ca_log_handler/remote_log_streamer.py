import socket
import time
from threading import Thread, Lock
from paramiko import SSHClient, AutoAddPolicy, SSHException
from framework.ca_log_handler.log_pattern_listener import PatternWatcher
from framework.log.logger import log


class RemoteLogStreamer:
    def __init__(self, remote_host, username, password, log_file_path, remote_log_path):
        self.thread = None
        self.remote_host = remote_host
        self.username = username
        self.password = password
        self.log_file_path = log_file_path
        self.remote_log_path = remote_log_path # Renamed for clarity
        self.ssh_client = None
        self.running = False
        self.last_position = None # Keep track of where we left off
        self.watchers = []
        self.watchers_lock = Lock()

    def _connect(self):
        """Establish an SSH connection with a timeout."""
        self.ssh_client = SSHClient()
        self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())

        self.ssh_client.connect(
            hostname=self.remote_host,
            username=self.username,
            password=self.password,
            timeout=10
        )

    def start_log_check(self, patterns, timeout=30):
        """
        Start watching for a list of regex patterns in the log stream.

        Args:
            patterns (list): List of regex strings to match.
            timeout (int): Maximum time to wait for patterns (in seconds).

        Returns:
            PatternWatcher: An object representing the active check. passed to get_log_check_result.
        """
        watcher = PatternWatcher(patterns, timeout)

        with self.watchers_lock:
            self.watchers.append(watcher)

        log.info(f"Remote log collector started log check for patterns: {patterns} with timeout {timeout}s")
        return watcher

    def get_log_check_result(self, watcher):
        """
        Get the result of a log check.

        Args:
            watcher (PatternWatcher): The watcher object returned by start_log_check.

        Returns:
            bool: True if all patterns were found, False if timeout occurred.
        """
        if not watcher.is_finished():
            elapsed = time.time() - watcher.start_time
            remaining = watcher.timeout - elapsed
            if remaining > 0:
                watcher.event.wait(remaining)

        success, matched = watcher.get_result()

        with self.watchers_lock:
            if watcher in self.watchers:
                self.watchers.remove(watcher)

        return success, matched

    def _dispatch_line(self, line):
        with self.watchers_lock:
            current_watchers = list(self.watchers)

            for watcher in current_watchers:
                watcher.check_log_pattern(line)



    def _stream_logs(self):
        while self.running:
            try:
                self._connect()
                stdin, stdout, stderr = self.ssh_client.exec_command(f"tail -F {self.remote_log_path}")

                with open(self.log_file_path, "a", buffering=1) as local_file:
                    for line in stdout:
                        if not self.running:
                            break
                        local_file.write(line)
                        local_file.flush()
                        self._dispatch_line(line)
            except (SSHException, socket.error) as e:
                log.info(f"Remote log collector Connection lost: {e}. Reconnecting...")
                time.sleep(5)
            finally:
                self._cleanup_ssh()

    def _cleanup_ssh(self):
        """Safely close the client without crashing."""
        try:
            if self.ssh_client:
                self.ssh_client.close()
        except Exception as e:
            log.warning("Remote log collector Error while closing SSH client, but ignoring since we're cleaning up. %s" % str(e))

    def start(self):
        self.running = True
        self.thread = Thread(target=self._stream_logs, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        self._cleanup_ssh()