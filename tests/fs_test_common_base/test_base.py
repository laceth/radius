from abc import ABC, abstractmethod


class FSTestCommonBase(ABC):
    # base class for all tests, defines test workflow.
    @abstractmethod
    def suite_setup(self):
        """
        Abstract method for suite-level setup.
        This method should be implemented by subclasses to perform setup actions
        before any tests in the suite are run.
        """
        pass

    @abstractmethod
    def suite_teardown(self):
        """
        Abstract method for suite-level teardown.
        This method should be implemented by subclasses to perform cleanup actions
        after all tests in the suite have finished.
        """
        pass

    @abstractmethod
    def do_setup(self):
        """
        Abstract method for test-level setup.
        This method should be implemented by subclasses to perform setup actions
        before each individual test execution.
        """
        pass

    @abstractmethod
    def do_test(self):
        """
        Abstract method for the test logic itself.
        This method must be implemented by subclasses to define the core test steps.
        """
        pass

    @abstractmethod
    def do_teardown(self):
        """
        Abstract method for test-level teardown.
        This method should be implemented by subclasses to perform cleanup actions
        after each individual test execution.
        """
        pass
