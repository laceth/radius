"""Vendor-agnostic helpers to configure RADIUS on switches."""
from typing import Any, Dict, Optional, Type

from framework.log.logger import log
from lib.switch.action import Action
from lib.switch.cisco_ios import CiscoIOS
from lib.switch.cisco_ios_radius_configure import CiscoIosRadiusConfigure
from lib.switch.radius_configure_base import RadiusConfigureBase
from lib.switch.switch_base import SwitchBase


class RadiusFactory:
    """Encapsulates vendor resolution and RADIUS setup/teardown orchestration."""

    def __init__(self) -> None:
        self.vendor_map: Dict[str, Type[RadiusConfigureBase]] = {
            "cisco_ios": CiscoIosRadiusConfigure,
        }
        # Cached radius_configure instance for reuse across setup/teardown
        self.radius_configure: Dict[str, RadiusConfigureBase] = {}

    def setup(self, switch: SwitchBase, port: str, radius_server_ip: str, radius_secret: str = "aristo", **kwargs: Any) -> bool:
        return self._handle_radius_action(
            self.vendor_map,
            Action.SETUP,
            switch=switch,
            port=port,
            radius_server_ip=radius_server_ip,
            radius_secret=radius_secret,
            **kwargs,
        )

    def teardown(self, switch: SwitchBase, port: str, radius_server_ip: str, **kwargs: Any) -> bool:
        return self._handle_radius_action(
            self.vendor_map,
            Action.TEARDOWN,
            switch=switch,
            port=port,
            radius_server_ip=radius_server_ip,
            **kwargs,
        )

    # Config loading is handled centrally by the framework's Configurator.
    # This module should not read files directly.
    # Switch lookup is performed upstream; callers should pass a switch config.

    # Backwards config-based resolution removed: tests now pass a SwitchBase instance directly.

    def _handle_radius_action(
        self,
        vendor_map: Dict[str, Type[RadiusConfigureBase]],
        action: Action,
        *,
        switch: SwitchBase,
        port: str,
        radius_server_ip: str,
        radius_secret: Optional[str] = None,
        **kwargs: Any,
    ) -> bool:
        try:
            # Derive connection details from the provided switch instance
            switch_ip = getattr(switch, "ip", "")
            username = getattr(switch, "username", None)
            password = getattr(switch, "password", None)
            vendor_type = "cisco_ios" if isinstance(switch, CiscoIOS) else "unknown"
            if not switch_ip or not username or not password:
                log.error("Missing IP or credentials for switch")
                return False

            radius_configure_cls = vendor_map.get(vendor_type)
            if not radius_configure_cls:
                log.error(f"Unsupported vendor '{vendor_type}' for switch {switch_ip}.")
                return False

            log.info(
                f"Starting RADIUS {action.name.lower()} on {vendor_type} switch {switch_ip}"
                f" (port {port}, server {radius_server_ip})"
            )

            # Retrieve or create a configurator instance per switch IP
            radius_configure = self.radius_configure.get(switch_ip)
            if radius_configure is None:
                radius_configure = radius_configure_cls(switch_ip, username, password)
                self.radius_configure[switch_ip] = radius_configure

            if action == Action.SETUP:
                if not radius_secret:
                    log.error("Secret is required when setting up RADIUS")
                    return False
                allowed_setup = {"mab", "vlan", "aaa_auth_type", "deadtime", "timeout", "retransmit"}
                setup_kwargs = {k: v for k, v in kwargs.items() if k in allowed_setup}
                result = radius_configure.setup_radius_config(port, radius_server_ip, radius_secret, **setup_kwargs)
            else:
                # No extra teardown kwargs needed; use driver's in-memory state
                result = radius_configure.teardown_radius_config(port, radius_server_ip)

            if result:
                log.info(f"Successfully {action.name.lower()} RADIUS on {switch_ip} port {port}")
            else:
                log.error(f"Failed to {action.name.lower()} RADIUS on {switch_ip} port {port}")
            return result

        except Exception as exc:
            log.error(f"RADIUS {action.name.lower()} failed for {switch_ip}: {exc}")
            return False
