from abc import ABC, abstractmethod
from typing import Any

from lib.switch.switch_base import SwitchBase


class RadiusConfigureBase(SwitchBase, ABC):
    """
    Abstract base class for RADIUS configuration on network switches.
    Provides switch connection state and RADIUS behavior contract.
    """

    def __init__(self, ip: str, username: str, password: str) -> None:
        super().__init__(ip, username, password)

    @abstractmethod
    def setup_radius_config(
        self,
        port: str,
        radius_server_ip: str,
        secret: str,
        **kwargs: Any,
    ) -> bool:
        """Configure RADIUS on a specific switch port. Vendor extras via kwargs."""
        pass

    @abstractmethod
    def teardown_radius_config(
        self,
        port: str,
        radius_server_ip: str,
        **kwargs: Any,
    ) -> bool:
        """Remove RADIUS configuration from a switch port. Vendor extras via kwargs."""
        pass
