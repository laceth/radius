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
    MAB = "802.1X authentication not enabled" # 802.1X disabled for MAB testing


class AuthNicProfile(Enum):
    """802.1X NIC profile types with their corresponding LAN profile XML files."""

    PEAP = "lan_profile_peap_config.xml"
    EAP_TLS = "lan_profile_eap_tls_config.xml"
    PEAP_EAP_TLS = "lan_profile_peap_eap_tls_config.xml"
    EAP_TTLS = "lan_profile_eap_ttls_config.xml"
    MAB = "lan_profile_mab_config.xml" # 802.1X disabled for MAB testing

class WindowsCert(Enum):
    CERT_TEMPLATE_CON_CERT = "testdecodeA.pfx"
    CERT_TEST_CLIENT = "clientcert.pfx"
    CERT_DOT1X_A = "Dot1x-CLT-A.pfx"

    CERT_DOT1X_EKU_B = "Dot1x-CLT-B.pfx"
    CERT_DOT1X_EKU_C = "Dot1x-CLT-C.pfx"
    CERT_DOT1X_EKU_D = "Dot1x-CLT-D.pfx"

    CERT_DOT1X_EKU_E = "Dot1x-CLT-E.pfx"
    CERT_DOT1X_EKU_F = "Dot1x-CLT-F.pfx"
    CERT_DOT1X_EKU_G = "Dot1x-CLT-G.pfx"

    CERT_Client_SAN = "Dot1x-CLT-G.pfx"

    CERT_DOT1X_MSCA_A = "Dot1xMSCA-CLT-A.pfx"
    CERT_DOT1X_MSCA_B = "Dot1xMSCA-CLT-B.pfx"
    CERT_DOT1X_MSCA_C = "Dot1xMSCA-CLT-C.pfx"
    CERT_DOT1X_MSCA_D = "Dot1xMSCA-CLT-D.pfx"

    CERT_DOT1X_MSCA_E = "Dot1xMSCA-CLT-E.pfx"
    CERT_DOT1X_MSCA_F = "Dot1xMSCA-CLT-F.pfx"
    CERT_DOT1X_MSCA_G = "Dot1xMSCA-CLT-G.pfx"  

    CERT_DOT1X_EXPIRED = "Dot1x-CLT-Expired.pfx"
    CERT_DOT1X_TIME = "Dot1x-CLT-Time.pfx"  # Certificate with absurd expiry date (12/31/9999)
    CERT_DOT1X_REVOKED = "Dot1x-CLT-Revoked.pfx"
    CERT_DOT1X_VALID   = "Dot1x-CLT-Good.pfx"
