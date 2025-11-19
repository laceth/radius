from framework.log.logger import log
from lib.plugin.radius import Radius
from lib.switch.cisco_ios import CiscoIOS
from typing import cast

class RadiusTestBase():

    def __init__(self, ca, radius, switch, version="1.0.0"):
        self.ca = ca
        self.version = version
        self.dot1x = cast(Radius, radius)
        self.switch = cast(CiscoIOS, switch)

    def do_setup(self):
        log.info("radius common setup")

    def radius_special_setup(self):
        log.info("radius special setup")

    def do_teardown(self):
        # Teardown code to clean up after tests
        log.info("radius common teardown")
