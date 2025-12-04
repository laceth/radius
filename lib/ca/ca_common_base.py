import paramiko
from framework.connection.ssh_client import SSHClient
from framework.log.logger import log
from framework.connection.connection_pool import CONNECTION_POOL


class CounterActBase(SSHClient):
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

    def get_conn_key(self):
        return self.ipaddress

    def _create_connection(self):
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
            return self.client
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.username}: {e}")

    def _execute(self, cmd, timeout=30):
        log.info(f"Executing command on CounterAct: {cmd}")
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if exit_code != 0:
            raise RuntimeError(f"Command '{cmd}' failed with exit code {exit_code}: {err}")
        return out

    def exec_command(self, cmd: str, timeout: int = 15) -> str:
        self.client = CONNECTION_POOL.get(self.get_conn_key(), self._create_connection)
        return self._execute(cmd, timeout)
