import time
from framework.log.logger import log
from framework.decorator.prametrizor import parametrize
from test.radius.radius_test_base import RadiusTestBase


class RadiusTestCommanExample(RadiusTestBase):
    def do_test(self):
        log.info("Check auth and properties")
        time.sleep(1)
        log.info(self.ca.exec_command("ifconfig"))
        log.info(self.em.exec_command("ifconfig"))
        self.dot1x.get_radius_status()
        self.switch.exec_command("show run")
        self.passthrough.execute_command("whoami")
        assert True


class RadiusTestSpecialSetupExample(RadiusTestBase):
    def do_setup(self):
        self.radius_special_setup()

    def do_test(self):
        log.info("Check auth and properties")
        time.sleep(1)
        self.dot1x.get_radius_status()
        assert False


@parametrize("username, password", [
    ("admin", "1234"),
    ("admin", "$%^&*(")
])
class RadiusTestPrametrized(RadiusTestBase):
    def do_test(self):
        log.info(f"Check Auth and properties")
        time.sleep(1)
        self.dot1x.get_radius_status()
        assert True
