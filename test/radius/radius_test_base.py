import time

from framework.decorator.annotation import component
from framework.log.logger import log
from lib.plugin.radius import Radius


@component(required=['ca', 'radius'])
class RadiusTestBase():

    def __init__(self, platform, dot1x):
        self.ca = platform
        self.dot1x = dot1x

    def do_setup(self):
        log.info("radius common setup")

    def radius_special_setup(self):
        log.info("radius special setup")

    def do_teardown(self):
        # Teardown code to clean up after tests
        log.info("radius common teardown")
