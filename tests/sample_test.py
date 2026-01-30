from tests.test_base import TestBase


class ExamplePositiveTest(TestBase):
    def do_setup(self):
        print("positive set_up")
        pass

    def do_test(self):
        print("Test Passed")
        assert True

    def do_teardown(self):
        print("teardown")


class NegativeExampleTest(TestBase):
    def do_setup(self):
        print("Negative set_up")
        pass

    def do_test(self):
        assert False, "Negative test failed"

    def do_teardown(self):
        print("teardown")
