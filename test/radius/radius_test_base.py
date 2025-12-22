from typing import cast

from framework.log.logger import log
from lib.ca.ca_common_base import CounterActBase
from lib.ca.em import EnterpriseManager
from lib.passthrough.passthrough_base import PassthroughBase
from lib.plugin.radius.radius import Radius
from lib.switch.cisco_ios import CiscoIOS
from lib.switch.radius_factory import RadiusFactory


class RadiusTestBase:
    def __init__(self, ca, em, radius, switch, passthrough, version="1.0.0"):
        self.ca = cast(CounterActBase, ca)
        self.em = cast(EnterpriseManager, em)
        self.version = version
        self.dot1x = cast(Radius, radius)
        self.switch = cast(CiscoIOS, switch)
        self.passthrough = cast(PassthroughBase, passthrough)
        self.rf = RadiusFactory()
        # Tests can construct and use RadiusFactory directly where needed

    def do_setup(self):
        log.info("radius common setup")
        self.rf.setup(self.switch, port=self.switch.port1, radius_server_ip=self.ca.ipaddress, radius_secret="aristo")

    def radius_special_setup(self):
        log.info("radius special setup")

    def do_teardown(self):
        # Teardown code to clean up after tests
        log.info("radius common teardown")
        self.rf.teardown(self.switch, port=self.switch.port1, radius_server_ip=self.ca.ipaddress)
