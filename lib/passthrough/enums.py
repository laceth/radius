"""
Enums for passthrough operations.
"""
from enum import Enum


class AuthenticationStatus(Enum):
    """802.1X authentication status values returned by `netsh lan show interfaces`."""

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


class WindowsCert(Enum):
    """
    Client certificate filenames located under:
      resources/radius/certificates/

    NOTE: Values are filenames (NOT full paths). CertificateAuthConfig._find_resource()
    resolves them to absolute paths.
    """

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


class MSCAEntry(Enum):
    """
    MSCA entries must match the UI/local.properties format used by the dot1x plugin.

    Example (must match exactly):
      '1.3.6.1.4.1.311.21.14 : szOID_CRL_SELF_CDP'
    """

    MS_CERT_SERVICES_CA_VERSION = "1.3.6.1.4.1.311.21.1 : MS Certificate Services CA Version"
    SZOID_CERTSRV_PREVIOUS_CERT_HASH = "1.3.6.1.4.1.311.21.2 : szOID_CERTSRV_PREVIOUS_CERT_HASH"
    SZOID_CRL_VIRTUAL_BASE = "1.3.6.1.4.1.311.21.3 : szOID_CRL_VIRTUAL_BASE"
    SZOID_CRL_NEXT_PUBLISH = "1.3.6.1.4.1.311.21.4 : szOID_CRL_NEXT_PUBLISH"
    SZOID_KP_CA_EXCHANGE = "1.3.6.1.4.1.311.21.5 : szOID_KP_CA_EXCHANGE"
    SZOID_KP_KEY_RECOVERY_AGENT = "1.3.6.1.4.1.311.21.6 : szOID_KP_KEY_RECOVERY_AGENT"
    SZOID_CERTIFICATE_TEMPLATE = "1.3.6.1.4.1.311.21.7 : szOID_CERTIFICATE_TEMPLATE"
    SZOID_ENTERPRISE_OID_ROOT = "1.3.6.1.4.1.311.21.8 : szOID_ENTERPRISE_OID_ROOT"
    SZOID_RDN_DUMMY_SIGNER = "1.3.6.1.4.1.311.21.9 : szOID_RDN_DUMMY_SIGNER"
    SZOID_APPLICATION_CERT_POLICIES = "1.3.6.1.4.1.311.21.10 : szOID_APPLICATION_CERT_POLICIES"
    SZOID_APPLICATION_POLICY_MAPPINGS = "1.3.6.1.4.1.311.21.11 : szOID_APPLICATION_POLICY_MAPPINGS"
    SZOID_APPLICATION_POLICY_CONSTRAINTS = "1.3.6.1.4.1.311.21.12 : szOID_APPLICATION_POLICY_CONSTRAINTS"
    SZOID_ARCHIVED_KEY_ATTR = "1.3.6.1.4.1.311.21.13 : szOID_ARCHIVED_KEY_ATTR"
    SZOID_CRL_SELF_CDP = "1.3.6.1.4.1.311.21.14 : szOID_CRL_SELF_CDP"
    SZOID_REQUIRE_CERT_CHAIN_POLICY = "1.3.6.1.4.1.311.21.15 : szOID_REQUIRE_CERT_CHAIN_POLICY"
    SZOID_ARCHIVED_KEY_CERT_HASH = "1.3.6.1.4.1.311.21.16 : szOID_ARCHIVED_KEY_CERT_HASH"
    SZOID_ISSUED_CERT_HASH = "1.3.6.1.4.1.311.21.17 : szOID_ISSUED_CERT_HASH"
    SZOID_DS_EMAIL_REPLICATION = "1.3.6.1.4.1.311.21.19 : szOID_DS_EMAIL_REPLICATION"
    SZOID_REQUEST_CLIENT_INFO = "1.3.6.1.4.1.311.21.20 : szOID_REQUEST_CLIENT_INFO"
    SZOID_ENCRYPTED_KEY_HASH = "1.3.6.1.4.1.311.21.21 : szOID_ENCRYPTED_KEY_HASH"
    SZOID_CERTSRV_CROSSCA_VERSION = "1.3.6.1.4.1.311.21.22 : szOID_CERTSRV_CROSSCA_VERSION"
    ENDORSEMENT_KEY_HIGH_ASSURANCE = "1.3.6.1.4.1.311.21.30 : Endorsement Key High Assurance"
    ENDORSEMENT_CERT_MEDIUM_ASSURANCE = "1.3.6.1.4.1.311.21.31 : Endorsement Certificate Medium Assurance"
    USER_CREDENTIALS_LOW_ASSURANCE = "1.3.6.1.4.1.311.21.32 : User Credentials Low Assurance"


class PreAdmissionRuleSet(Enum):
    """
    Canonical rule sets for tests (avoid hardcoding dictionaries in test classes).

    The list values are compatible with:
      Radius.set_pre_admission_rules(rules: list)
    """

    # -------------------------
    # T1316959
    # -------------------------

    # Rule 1: select .1 and .14
    T1316959_RULE1 = [
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
                MSCAEntry.MS_CERT_SERVICES_CA_VERSION.value,
                MSCAEntry.SZOID_CRL_SELF_CDP.value,
            ],
        }
    ]

    # Rule 2: (.5 + .19) AND (.11 + .19) as two separate criteria rows
    T1316959_RULE2 = [
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
                MSCAEntry.SZOID_KP_CA_EXCHANGE.value,
                MSCAEntry.SZOID_DS_EMAIL_REPLICATION.value,
            ],
        },
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
                MSCAEntry.SZOID_APPLICATION_POLICY_MAPPINGS.value,
                MSCAEntry.SZOID_DS_EMAIL_REPLICATION.value,
            ],
        },
    ]

    # -------------------------
    # T1316958
    # -------------------------

    # Step 1: select .2, .4, .6, .8, .14, .16, .22, .32
    T1316958_RULE1_ALL = [
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
                MSCAEntry.SZOID_CERTSRV_PREVIOUS_CERT_HASH.value,  # .2
                MSCAEntry.SZOID_CRL_NEXT_PUBLISH.value,            # .4
                MSCAEntry.SZOID_KP_KEY_RECOVERY_AGENT.value,       # .6
                MSCAEntry.SZOID_ENTERPRISE_OID_ROOT.value,         # .8
                MSCAEntry.SZOID_CRL_SELF_CDP.value,                # .14
                MSCAEntry.SZOID_ARCHIVED_KEY_CERT_HASH.value,      # .16
                MSCAEntry.SZOID_CERTSRV_CROSSCA_VERSION.value,     # .22
                MSCAEntry.USER_CREDENTIALS_LOW_ASSURANCE.value,    # .32
            ],
        }
    ]

    # Step 3: deselect ".2" only (remove 21.2)
    T1316958_RULE1_NO_2 = [
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
                MSCAEntry.SZOID_CRL_NEXT_PUBLISH.value,            # .4
                MSCAEntry.SZOID_KP_KEY_RECOVERY_AGENT.value,       # .6
                MSCAEntry.SZOID_ENTERPRISE_OID_ROOT.value,         # .8
                MSCAEntry.SZOID_CRL_SELF_CDP.value,                # .14
                MSCAEntry.SZOID_ARCHIVED_KEY_CERT_HASH.value,      # .16
                MSCAEntry.SZOID_CERTSRV_CROSSCA_VERSION.value,     # .22
                MSCAEntry.USER_CREDENTIALS_LOW_ASSURANCE.value,    # .32
            ],
        }
    ]

    # Step 4: unselect all but ".14" and ".22"
    T1316958_RULE1_ONLY_14_22 = [
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
                MSCAEntry.SZOID_CRL_SELF_CDP.value,             # .14
                MSCAEntry.SZOID_CERTSRV_CROSSCA_VERSION.value,  # .22
            ],
        }
    ]

    # Step 5: unselect all but ".14" and ".32"
    T1316958_RULE1_ONLY_14_32 = [
        {
            "rule_name": "Certificate-MS-Certificate-Authority",
            "fields": [
                MSCAEntry.SZOID_CRL_SELF_CDP.value,             # .14
                MSCAEntry.USER_CREDENTIALS_LOW_ASSURANCE.value, # .32
            ],
        }
    ]
