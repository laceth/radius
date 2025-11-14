from typing import Tuple

import paramiko

class CounterActBase:
    session = None
    username = None
    password = None
    ipaddress = None
    is_ipv4 = None
    is_ha = None
    client = None

    def __init__(self, ip: str, user_name: str, password: str, version, is_ipv4=True, is_ha=False) -> None:
        self.ipaddress = ip
        self.username = user_name
        self.password = password
        self.is_ipv4 = is_ipv4
        self.is_ha = is_ha
        self.is_ipv4 = True
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                hostname=self.ipaddress,
                port=22,
                username=self.username,
                password=self.password,
                look_for_keys=False,  # Don’t use any SSH keys
                allow_agent=False,    # Don’t use SSH agent
                timeout=10
            )
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.hostname}: {e}")

    def exec_command(self, command: str, timeout: int = 15) -> str:
        """
        Execute a shell command on the remote machine.

        Returns:
            (exit_code, stdout, stderr)
        """
        if not self.client:
            raise RuntimeError("SSH connection not established. Call connect() first.")

        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if exit_code != 0:
            raise RuntimeError(f"Command '{command}' failed with exit code {exit_code}: {err}")
        return out

    def close(self):
        """Close the SSH connection."""
        if self.client:
            self.client.close()
            self.client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

if __name__ == "__main__":
    c = CounterActBase("10.16.177.65", "root", "aristo1")

