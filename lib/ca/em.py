import logging

from lib.ca.ca_common_base import CounterActBase
RESTART_EM_COMMAND = "fstool service restart"

class EnterpriseManager(CounterActBase):
    def __int__(self, ca: CounterActBase):
        super().__init__()
        self.ca = ca

    def restart_service(self) -> bool:
        logging.info("Restarting Enterprise Manager service...")
