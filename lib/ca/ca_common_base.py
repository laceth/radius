import re
import time
import paramiko
from typing import List, Optional
from framework.connection.ssh_client import SSHClient
from framework.log.logger import log
from framework.connection.connection_pool import CONNECTION_POOL
import xml.etree.ElementTree as ET
import os

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

    def scp_file(self, local_path: str, remote_path: str, direction: str = "upload", timeout: int = 15) -> None:
        """
        Transfer a file using SCP.

        Args:
            local_path: Path to the local file.
            remote_path: Path to the remote file.
            direction: "upload" to send the file, "download" to retrieve the file.
            timeout: Timeout for the SCP operation.

        Raises:
            ValueError: If the direction is invalid.
            RuntimeError: If the SCP operation fails.
        """
        self.client = CONNECTION_POOL.get(self.get_conn_key(), self._create_connection)
        try:
            with self.client.open_sftp() as sftp:
                if direction == "upload":
                    log.info(f"Uploading file {local_path} to {remote_path}")
                    sftp.put(local_path, remote_path)
                elif direction == "download":
                    log.info(f"Downloading file {remote_path} to {local_path}")
                    sftp.get(remote_path, local_path)
                else:
                    raise ValueError("Invalid direction. Use 'upload' or 'download'.")
        except Exception as e:
            raise RuntimeError(f"SCP operation failed: {e}")

    def simple_policy_condition(self, policy_file_name, policy_name, fields):
        """
        Build and import simple condition policies.
        fields input ie.
        [
        {
            "EXPR_TYPE": "SIMPLE",
            "CONDITION": {
                "EMPTY_LIST_VALUE": "false",
                "FIELD_NAME": "mac",
                "LABEL": "MAC Address",
                "LEFT_PARENTHESIS": "0",
                "LOGIC": "AND",
                "RET_VALUE_ON_UKNOWN": "IRRESOLVED",
                "RIGHT_PARENTHESIS": "0",
                "FILTER": {
                    "CASE_SENSITIVE": "false",
                    "TYPE": "equals",
                    "VALUE": {
                        "VALUE2": "0050568513ca"
                    }
                }
            }
        },
        {
            "EXPR_TYPE": "SIMPLE",
            "CONDITION": {
                "EMPTY_LIST_VALUE": "false",
                "FIELD_NAME": "access_ip",
                "LABEL": "Access IP",
                "LEFT_PARENTHESIS": "0",
                "LOGIC": "AND",
                "RET_VALUE_ON_UKNOWN": "IRRESOLVED",
                "RIGHT_PARENTHESIS": "0",
                "FILTER": {
                    "CASE_SENSITIVE": "false",
                    "TYPE": "equals",
                    "VALUE": {
                        "VALUE2": "1.1.1.1"
                    }
                }
            }
        }
    ]
        Args:
            policy_file_name (str): Name of the policy file.
            policy_name (str): Name of the policy.
            fields (list): List of dictionaries with 'field_name', 'field_label', and 'field_value'.
            em_policy_path (str): Path to save the modified policy file.
        """
        log.info(f"******** adding policy {policy_name} ********")
        modified_policy_path = f"/tmp/{policy_file_name}"
        current_dir = os.path.dirname(__file__)
        relative_path = os.path.join(current_dir, '../../resources/policy/simple_condition_base_policy.xml')

        os.system(f"cp {relative_path} {modified_policy_path}")

        # Parse the XML file
        tree = ET.parse(modified_policy_path)
        root = tree.getroot()
        # Update the policy name
        rule = root.find("./RULE")
        if rule is not None:
            rule.set("NAME", policy_name)
        # Add or update the EXPRESSION block
        expression = ET.Element("EXPRESSION")
        if len(fields) > 1:
            expression.set("EXPR_TYPE", "AND")
            for field in fields:
                sub_expression = ET.SubElement(expression, "EXPRESSION", {"EXPR_TYPE": field["EXPR_TYPE"]})
                condition = ET.SubElement(sub_expression, "CONDITION", {**field["CONDITION"]})
                filter_element = ET.SubElement(condition, "FILTER", {**field["CONDITION"]["FILTER"]})
                ET.SubElement(filter_element, "VALUE", {**field["CONDITION"]["FILTER"]["VALUE"]})
        else:
            field = fields[0]
            expression.set("EXPR_TYPE", field["EXPR_TYPE"])
            condition = ET.SubElement(expression, "CONDITION", {**field["CONDITION"]})
            filter_element = ET.SubElement(condition, "FILTER", {**field["CONDITION"]["FILTER"]})
            ET.SubElement(filter_element, "VALUE", {**field["CONDITION"]["FILTER"]["VALUE"]})

        # Insert the EXPRESSION block into the RULE
        existing_expression = rule.find("./EXPRESSION")
        if existing_expression is not None:
            rule.remove(existing_expression)
        rule.append(expression)

        # Save the modified XML file
        tree.write(modified_policy_path, encoding="utf-8", xml_declaration=True)
        remote_path = f"/tmp/{policy_file_name}"
        self.scp_file(local_path=modified_policy_path, remote_path=remote_path, direction="upload")
        try:
            log.info(f"removing {policy_name} if exists")
            self.remove_policy(policy_name)
        except RuntimeError as e:
            log.debug(f"Policy {policy_name} removal failed or not exist, continue to add new policy: {e}")
        self.import_policy(remote_path)
        log.info(f"Policy {policy_name} added successfully")

    def remove_policy(self, policy_name: str) -> None:
        output = self.exec_command(f"fstool cliapi policy remove {policy_name}")
        if "removed" not in output:
            raise RuntimeError(f"Policy removal failed: {output}")
        log.info(f"Policy {policy_name} removed successfully")

    def import_policy(self, policy_file_path: str) -> None:
        output = self.exec_command(f"fstool cliapi policy import {policy_file_path}")
        if "Import policy completed" not in output:
            raise RuntimeError(f"Policy import failed: {output}")

    def check_policy_match(self, policy_name: str, count: int = 1, timeout: int = 30, retry_interval: int = 5) -> bool:
        """
        Check if a policy matches the expected count, with retries until a timeout.

        Args:
            policy_name: Name of the policy to check.
            count: Expected match count (default: 1).
            timeout: Maximum time in seconds to keep retrying (default: 30).
            retry_interval: Delay between retries in seconds (default: 2).

        Returns:
            True if the policy matches the expected count within the timeout, False otherwise.
        """
        log.info(f"Checking policy match '{policy_name}'")
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                output = self.exec_command(f"fstool npstats | grep '{policy_name}'")
            except RuntimeError as e:
                log.debug(f"Failed to get policy stats for '{policy_name}': {e}")
                time.sleep(retry_interval)
                continue
            match = re.search(r'MATCH\s*:\s*(\d+)', output)
            if match and int(match.group(1)) == count:
                log.info(f"Policy '{policy_name}' matched expected count {count}")
                return True
            log.debug(f"Policy '{policy_name}' did not match. Retrying in {retry_interval} seconds...")
            time.sleep(retry_interval)
        log.debug(f"Policy '{policy_name}' did not match the expected count within {timeout} seconds.")
        return False

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

