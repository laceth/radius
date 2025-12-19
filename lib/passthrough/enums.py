"""
Enums for passthrough operations.
"""
from enum import Enum


class AuthenticationStatus(Enum):
    """802.1X authentication status values returned by netsh lan show interfaces."""

    SUCCEEDED = "Authentication succeeded"
    FAILED = "Authentication failed"
    IN_PROGRESS = "Authenticating"
    NOT_STARTED = "Not started"
    DISABLED = "Disabled"


class AuthNicProfile(Enum):
    """802.1X NIC profile types with their corresponding LAN profile XML files."""

    PEAP = "lan_profile_peap_config.xml"
    EAP_TLS = "lan_profile_eap_tls_config.xml"
    PEAP_EAP_TLS = "lan_profile_peap_eap_tls_config.xml"
    EAP_TTLS = "lan_profile_eap_ttls_config.xml"

    @property
    def profile_filename(self) -> str:
        """Return the LAN profile XML filename for this NIC profile type."""
        return self.value


