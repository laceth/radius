import logging

from lib.ca.ca_common_base import CounterActBase
RESTART_EM_COMMAND = "fstool service restart"

class EnterpriseManager(CounterActBase):
    def __int__(self, ca: CounterActBase):
        super().__init__()
        self.ca = ca

    def restart_service(self) -> bool:
        logging.info("Restarting Enterprise Manager service...")

    def run_tech_support_health_check(self, hours: int = 24, timeout: int = 300) -> str:
        """
        Run ``fstool tech-support --health-check --oneach-all -t 24h --exclude local_patches`` on the EM and
        assert that no appliances report errors.

        Note: Checking for ``OK : No issues found`` alone is **not** sufficient
        because the summary may contain both ``OK`` and ``Errors`` lines, e.g.::

            Errors : Detected 2 incidents on 1 devices
            OK : No issues found on 1 devices

        This corresponds to Step 1 of CSV C148464 (T1316961).

        Args:
            hours: Time window in hours to inspect (``-t <hours>h``).
            timeout: SSH command timeout in seconds.

        Returns:
            The full command output.

        Raises:
            AssertionError: If the output contains an ``Errors`` summary line.
        """
        cmd = (
            f"fstool tech-support --health-check --oneach-all "
            f"-t {hours}h --exclude local_patches"
        )
        logging.info(f"Running health check on EM: {cmd}")
        output = self.exec_command(cmd, timeout=timeout, log_output=True, log_command=True)
        assert "Errors" not in output, (
            f"Health check reported errors on one or more appliances.\nOutput:\n{output}"
        )
        logging.info("Health check completed — no errors reported")
        return output

