"""
Parsing helpers for ``fstool dot1x status`` and ``fstool oneach fstool dot1x status`` output.

Kept in a dedicated module so both :class:`~lib.plugin.radius.radius.Radius` and
:class:`~lib.ca.em.EnterpriseManager` can import the utilities without any
circular-dependency risk and without cluttering either class with static helpers.
"""

import re

# The main 802.1x plugin process name as it appears in 'fstool dot1x status' output.
# Example line: "802.1x plugin (pid 10659) is running for 21-04:27:54."
DOT1X_PLUGIN_PROCESS_NAME = "802.1x plugin"
DOT1X_REQUIRED_PROCESSES = ("radiusd", "winbindd", "redis-server")


def parse_process_uptime_seconds(status_output: str, process_name: str) -> int:
    """
    Extract a sub-process uptime in seconds from ``fstool dot1x status`` output.

    Looks for lines like::

        radiusd (pid 28055) is running for 00:54.
        winbindd (pid 27705) of txqalab is running for 01:01.
        802.1x plugin (pid 10659) is running for 21-04:27:54.

    Supported time formats: ``MM:SS``, ``HH:MM:SS``, ``DAYS-HH:MM:SS``.

    Args:
        status_output: Full output of ``fstool dot1x status``.
        process_name:  Process to look for (e.g. ``'radiusd'``, ``'winbindd'``,
                       ``'redis-server'``, ``'802.1x plugin'``).

    Returns:
        Uptime in seconds, or ``-1`` if the process line is not found or
        the time string is not parseable.
    """
    for line in status_output.splitlines():
        if process_name in line.lower() and "is running for" in line:
            m = re.search(r"is running for\s+(.+)", line)
            if not m:
                continue
            time_str = m.group(1).strip().rstrip(".")

            # DAYS-HH:MM:SS
            p = re.match(r"^(\d+)-(\d{2}):(\d{2}):(\d{2})$", time_str)
            if p:
                return (
                    int(p.group(1)) * 86400
                    + int(p.group(2)) * 3600
                    + int(p.group(3)) * 60
                    + int(p.group(4))
                )
            # HH:MM:SS
            p = re.match(r"^(\d{2,}):(\d{2}):(\d{2})$", time_str)
            if p:
                return int(p.group(1)) * 3600 + int(p.group(2)) * 60 + int(p.group(3))
            # MM:SS
            p = re.match(r"^(\d{2,}):(\d{2})$", time_str)
            if p:
                return int(p.group(1)) * 60 + int(p.group(2))

            return -1
    return -1


def parse_all_process_uptimes(status_output: str) -> dict:
    """
    Parse a ``fstool dot1x status`` output block and return uptime (seconds) for
    every tracked process.

    Args:
        status_output: Full output of ``fstool dot1x status``.

    Returns:
        dict mapping process name → uptime in seconds (or ``-1`` if not running /
        not found).  Example::

            {"802.1x plugin": 7654, "radiusd": 120, "winbindd": 118, "redis-server": 125}
    """
    all_processes = (DOT1X_PLUGIN_PROCESS_NAME,) + DOT1X_REQUIRED_PROCESSES
    return {
        proc: parse_process_uptime_seconds(status_output, proc)
        for proc in all_processes
    }


def split_oneach_output(oneach_output: str) -> dict:
    """
    Split ``fstool oneach …`` output into per-device sections.

    Handles the common Forescout format where each appliance section starts
    with a line that is just the appliance IP / hostname followed by ``:``,
    e.g.::

        10.0.0.1:
        802.1x plugin (pid 10659) is running for 21-04:27:54.
        radiusd (pid 28055) is running for 02:14.
        ...

        10.0.0.2:
        802.1x plugin (pid 10660) is running for 20-12:00:01.
        ...

    Args:
        oneach_output: Full output of ``fstool oneach fstool dot1x status``.

    Returns:
        dict mapping device identifier (IP / hostname string) → output block
        string for that device.
    """
    sections: dict = {}
    current_device: str | None = None
    current_lines: list = []

    for line in oneach_output.splitlines():
        stripped = line.strip()
        # A device header is a non-empty token (IP or hostname) followed by ':'
        # with nothing else on the line.
        if stripped and re.match(r"^[\w.\-]+:$", stripped):
            if current_device is not None:
                sections[current_device] = "\n".join(current_lines)
            current_device = stripped.rstrip(":")
            current_lines = []
        elif current_device is not None:
            current_lines.append(line)

    if current_device is not None:
        sections[current_device] = "\n".join(current_lines)

    return sections

