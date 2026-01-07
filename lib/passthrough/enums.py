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


# need Enum for windows cert here and group.
class WindowsCertStore(Enum):
    """Windows Certificate Store locations."""

    TEST_DECODE_A = "testdecodeA.pfx"
    TEST_DECODE_B = "clientcert.pfx"
    DOT1X_CLT_E = "Dot1x-CLT-E.pfx"
    DOT1X_CLT_F = "Dot1x-CLT-F.pfx"
    DOT1X_CLT_G = "Dot1x-CLT-G.pfx"
    DOT1X_MSCA_B = "Dot1xMSCA-CLT-B.pfx"
    DOT1X_MSCA_C = "Dot1xMSCA-CLT-C.pfx"
    DOT1X_MSCA_D = "Dot1xMSCA-CLT-D.pfx"
    DOT1X_MSCA_E = "Dot1xMSCA-CLT-E.pfx"
    DOT1X_MSCA_F = "Dot1xMSCA-CLT-F.pfx"
    DOT1X_MSCA_G = "Dot1xMSCA-CLT-G.pfx"
