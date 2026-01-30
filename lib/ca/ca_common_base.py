import paramiko
from typing import List, Optional
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

    def __init__(self, ip: str, user_name: str, password: str, version: str, is_ipv4=True, is_ha=False) -> None:
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
        log.debug(f"Executing command on CounterAct: {cmd}")
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

    def get_host_ip_by_mac(self, mac_address: str) -> str:
        """
        Get host IP by MAC address.

        Args:
            mac_address: MAC address to search for

        Returns:
            IP address if found

        Raises:
            Exception: If MAC address not found on CA
        """
        cmd = f"fstool hostinfo all | grep 'mac,' | grep {mac_address}"
        output = self.exec_command(cmd)

        if not output:
            raise Exception(f"MAC address {mac_address} not found on CA")

        # Parse IP from output: "10.1.2.3,mac,..."
        ip = output.split("\n")[0].split(',')[0]
        log.info(f"Found IP {ip} for MAC {mac_address}")
        return ip

    def get_host_id_by_ip(self, host_ip: str) -> str:
        """
        Get host ID by IP address.

        Args:
            host_ip: IP address of the host

        Returns:
            Host ID if found, falls back to IP if not found
        """
        try:
            cmd = f"fstool hostinfo {host_ip} | grep 'host_id'"
            output = self.exec_command(cmd)

            if output and ',' in output:
                host_id = output.split(',')[-1].strip()
                log.info(f"Found host ID {host_id} for IP {host_ip}")
                return host_id
        except RuntimeError:
            # grep returns exit code 1 when no match found
            pass

        log.info(f"host_id not found, using IP {host_ip} as identifier")
        return host_ip

    def delete_endpoint(self, endpoint_ip: str) -> bool:
        """
        Delete RADIUS endpoint by IP address.

        Args:
            endpoint_ip: IP address of the endpoint to delete

        Returns:
            True if removed successfully, False otherwise
        """
        try:
            endpoint_id = self.get_host_id_by_ip(endpoint_ip)
            log.info(f"Deleting endpoint with ID: {endpoint_id}")

            cmd = f"fstool oneach fstool cliapi host remove {endpoint_id}"
            output = self.exec_command(cmd)

            if "Removed" not in output:
                log.error(f"Remove endpoint {endpoint_id} failed: {output}")
                return False

            log.info(f"Endpoint {endpoint_id} removed successfully")
            return True

        except Exception as e:
            log.error(f"Failed to remove endpoint {endpoint_ip}: {e}")
            return False

    def check_properties(self, id: str, properties_check_list: List[dict]) -> None:
        """
        Check multiple properties of a host.

        Args:
            id: Host identifier (IP address or MAC address)
            properties_check_list: List of dicts with 'property_field' and 'expected_value'

        Raises:
            NotImplementedError: Subclass must implement this method
        """
        raise NotImplementedError("Subclass must implement check_properties")

    def get_property_value(self, id: str, property_field: str) -> Optional[str]:
        """
        Get the value of a property for a host.

        Args:
            id: Host identifier (IP address or MAC address)
            property_field: The property field to retrieve

        Returns:
            Property value or None if not found

        Raises:
            NotImplementedError: Subclass must implement this method
        """
        raise NotImplementedError("Subclass must implement get_property_value")

