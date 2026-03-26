import logging

from lib.ca.ca_common_base import CounterActBase
from lib.plugin.radius.dot1x_status_parser import parse_all_process_uptimes, split_oneach_output
from lib.plugin.radius.radius import DOT1X_STATUS_COMMAND, DOT1X_ONEACH_STATUS_COMMAND

RESTART_EM_COMMAND = "fstool service restart"


class EnterpriseManager(CounterActBase):
    def __int__(self, ca: CounterActBase):
        super().__init__()
        self.ca = ca

    def restart_service(self) -> bool:
        logging.info("Restarting Enterprise Manager service...")

    def get_dot1x_status_all(self, timeout: int = 30) -> dict:
        """
        Run ``fstool dot1x status`` on the EM itself and
        ``fstool oneach fstool dot1x status`` on all CAs, then return a
        combined uptime map for every appliance.

        This corresponds to Step 2 of TC-9262 / TC-9264, which requires both:
            - ``fstool dot1x status``          (EM's own dot1x processes)
            - ``fstool oneach fstool dot1x status``  (each CA's dot1x processes)

        Args:
            timeout: SSH command timeout in seconds.

        Returns:
            dict[str, dict[str, int]] mapping a device label to a process →
            uptime-in-seconds dict (or -1 when a process is not running)::

                {
                    "EM": {"802.1x plugin": 7654, "radiusd": 120, ...},
                    "CA 10.0.0.2": {"802.1x plugin": 7654, "radiusd": 118, ...},
                    ...
                }
        """
        all_statuses: dict = {}

        # --- EM itself ---
        logging.info(f"Running '{DOT1X_STATUS_COMMAND}' on EM {self.ipaddress}")
        em_output = self.exec_command(DOT1X_STATUS_COMMAND, timeout=timeout, log_output=True)
        all_statuses["EM"] = parse_all_process_uptimes(em_output)

        # --- All CAs via oneach ---
        logging.info(f"Running '{DOT1X_ONEACH_STATUS_COMMAND}' on EM {self.ipaddress}")
        oneach_output = self.exec_command(DOT1X_ONEACH_STATUS_COMMAND, timeout=timeout, log_output=True)
        for device_id, section_output in split_oneach_output(oneach_output).items():
            all_statuses[f"CA {device_id}"] = parse_all_process_uptimes(section_output)

        return all_statuses

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

