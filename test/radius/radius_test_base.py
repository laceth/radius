from framework.log.logger import log
from lib.ca.ca_common_base import CounterActBase
from lib.ca.em import EnterpriseManager
from lib.passthrough.passthrough_base import PassthroughBase
from lib.plugin.radius.radius import Radius
from lib.switch.cisco_ios import CiscoIOS
from typing import cast

class RadiusTestBase():

    def __init__(self, ca, em, radius, switch, passthrough, version="1.0.0"):
        self.ca = cast(CounterActBase, ca)
        self.em = cast(EnterpriseManager, em)
        self.version = version
        self.dot1x = cast(Radius, radius)
        self.switch = cast(CiscoIOS, switch)
        self.passthrough = cast(PassthroughBase, passthrough)

    def do_setup(self):
        log.info("radius common setup")

    def radius_special_setup(self):
        log.info("radius special setup")

    def do_teardown(self):
        # Teardown code to clean up after tests
        log.info("radius common teardown")
