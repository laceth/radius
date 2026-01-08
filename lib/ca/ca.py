from framework.log.logger import log
from lib.ca.ca_common_base import CounterActBase

# Command
REMOVE_ENDPOINT_CMD = "fstool cliapi host remove %s"
GET_HOSTINFO_CMD = "fstool hostinfo %s"


class CouterActAppliance(CounterActBase):
    def __int__(self, ca: CounterActBase):
        super().__init__()

    def clear_endpoint_by_id(self, id: str):
        log.info(f"Clearing endpoint with ID: {id}")
        cmd = REMOVE_ENDPOINT_CMD % id
        output = self.exec_command(cmd)
        log.info(f"Command output: {output}")

    def get_id_by_mac(self, mac: str):
        cmd = GET_HOSTINFO_CMD % mac
        output = self.exec_command(cmd)
        if output == "":
            raise Exception("mac given not found on CA")
        return output.split("\n")[0].split(",")[0]

    def property_check(self, id: str, property_field: str, expected_value: str, resovled_by: str = ""):
        log.info(f"Checking property '{property_field}' for IP '{id}' with expected value '{expected_value}'")
