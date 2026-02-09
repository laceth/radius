"""
Enums for RADIUS.
"""
from enum import Enum


class RadiusAuthStatus(str, Enum):
    """RADIUS authentication status values as shown in CounterAct."""
    ACCESS_ACCEPT = "Access-Accept"
    ACCESS_REJECT = "Access-Reject"


class LdapPorts(Enum):
    """
    LDAP port modes for Active Directory queries.
    """
    
    STANDARD_LDAP_TLS = "standard ldap over tls"      # 636
    STANDARD_LDAP = "standard ldap"                   # 389
    GLOBAL_CATALOG = "global catalog"                 # 3268
    GLOBAL_CATALOG_TLS = "global catalog over tls"    # 3269

class Dot1xAttribute(str, Enum):
    CERT_EAP_TLS_TEMPLATE = "Certificate-EAP-TLS-Certificate-Template"
    CERT_FROM_SUBJECT_ALTERNATIVE_NAME = "Certificate-Subject-Alternative-Name"

class MscaOid(str, Enum):
    TEMPLATE_OID_01 = "1.3.6.1.4.1.311.21.8.8341934.12872887.10702751.6378467.15326267.45.7566079.10113853"
    TEMPLATE_OID_02_REGEX = r"1.3.6.*[6-8].8341934.12872887.10702751.6378467.15326267.[30-45].*"

class EKUEntry(str, Enum):
    EKU_01_SERVER_AUTH = "1.3.6.1.5.5.7.3.1 : serverAuth"
    EKU_02_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2 : clientAuth"
    EKU_03_CODE_SIGNING = "1.3.6.1.5.5.7.3.3 : codeSigning"
    EKU_04_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4 : emailProtection"
    EKU_05_IPSEC_IKE = "1.3.6.1.5.5.7.3.5 : ipsecIKE"
    EKU_06_IPSEC_TUNNEL = "1.3.6.1.5.5.7.3.6 : ipsecTunnel"
    EKU_07_IPSEC_USER = "1.3.6.1.5.5.7.3.7 : ipsecUser"
    EKU_08_TIMESTAMPING = "1.3.6.1.5.5.7.3.8 : timeStamping"
    EKU_09_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9 : OCSPSigning"
    EKU_10_SSH_AUTHENTICATION = "1.3.6.1.5.5.7.3.10 : Secure Shell (SSH) Authentication"
    EKU_11_SBGP_CERT_AA_SERVER_AUTH = "1.3.6.1.5.5.7.3.11 : sbgpCertAAServerAuth"
    EKU_12_SCVP_RESPONDER = "1.3.6.1.5.5.7.3.12 : id-kp-scvp-responder"
    EKU_13_EAP_OVER_PPP = "1.3.6.1.5.5.7.3.13 : id-kp-eapOverPPP"
    EKU_14_EAP_OVER_LAN = "1.3.6.1.5.5.7.3.14 : id-kp-eapOverLAN"
    EKU_15_SCVP_SERVER = "1.3.6.1.5.5.7.3.15 : id-kp-scvpServer"
    EKU_16_SCVP_CLIENT = "1.3.6.1.5.5.7.3.16 : id-kp-scvpClient"
    EKU_17_ID_KP_IPSEC_IKE = "1.3.6.1.5.5.7.3.17 : id-kp-ipsecIKE"
    EKU_18_CAPWAP_AC = "1.3.6.1.5.5.7.3.18 : id-kp-capwapAC"
    EKU_19_CAPWAP_WTP = "1.3.6.1.5.5.7.3.19 : id-kp-capwapWTP"
    EKU_20_SIP_DOMAIN = "1.3.6.1.5.5.7.3.20 : id-kp-sipDomain"
    EKU_21_SECURE_SHELL_CLIENT = "1.3.6.1.5.5.7.3.21 : secureShellClient"
    EKU_22_SECURE_SHELL_SERVER = "1.3.6.1.5.5.7.3.22 : secureShellServer"
    EKU_23_SEND_ROUTER = "1.3.6.1.5.5.7.3.23 : id-kp-sendRouter"
    EKU_24_SEND_PROXY = "1.3.6.1.5.5.7.3.24 : id-kp-sendProxy"
    EKU_25_SEND_OWNER = "1.3.6.1.5.5.7.3.25 : id-kp-sendOwner"
    EKU_26_SEND_PROXIED_OWNER = "1.3.6.1.5.5.7.3.26 : id-kp-sendProxiedOwner"
    EKU_27_CMC_CA = "1.3.6.1.5.5.7.3.27 : id-kp-cmcCA"
    EKU_28_CMC_RA = "1.3.6.1.5.5.7.3.28 : id-kp-cmcRA"
    EKU_29_CMC_ARCHIVE = "1.3.6.1.5.5.7.3.29 : id-kp-cmcArchive"

class MSCAEntry(Enum):
    OID_21_01_MS_CERT_SERVICES_CA_VERSION = ("1.3.6.1.4.1.311.21.1 : MS Certificate Services CA Version")
    OID_21_02_SZOID_CERTSRV_PREVIOUS_CERT_HASH = ("1.3.6.1.4.1.311.21.2 : szOID_CERTSRV_PREVIOUS_CERT_HASH")
    OID_21_03_SZOID_CRL_VIRTUAL_BASE = ("1.3.6.1.4.1.311.21.3 : szOID_CRL_VIRTUAL_BASE")
    OID_21_04_SZOID_CRL_NEXT_PUBLISH = ("1.3.6.1.4.1.311.21.4 : szOID_CRL_NEXT_PUBLISH")
    OID_21_05_SZOID_KP_CA_EXCHANGE = ("1.3.6.1.4.1.311.21.5 : szOID_KP_CA_EXCHANGE")
    OID_21_06_SZOID_KP_KEY_RECOVERY_AGENT = ("1.3.6.1.4.1.311.21.6 : szOID_KP_KEY_RECOVERY_AGENT")
    OID_21_07_SZOID_CERTIFICATE_TEMPLATE = ("1.3.6.1.4.1.311.21.7 : szOID_CERTIFICATE_TEMPLATE")
    OID_21_08_SZOID_ENTERPRISE_OID_ROOT = ("1.3.6.1.4.1.311.21.8 : szOID_ENTERPRISE_OID_ROOT")
    OID_21_09_SZOID_RDN_DUMMY_SIGNER = ("1.3.6.1.4.1.311.21.9 : szOID_RDN_DUMMY_SIGNER")
    OID_21_10_SZOID_APPLICATION_CERT_POLICIES = ("1.3.6.1.4.1.311.21.10 : szOID_APPLICATION_CERT_POLICIES")
    OID_21_11_SZOID_APPLICATION_POLICY_MAPPINGS = ("1.3.6.1.4.1.311.21.11 : szOID_APPLICATION_POLICY_MAPPINGS")
    OID_21_12_SZOID_APPLICATION_POLICY_CONSTRAINTS = ("1.3.6.1.4.1.311.21.12 : szOID_APPLICATION_POLICY_CONSTRAINTS")
    OID_21_13_SZOID_ARCHIVED_KEY_ATTR = ("1.3.6.1.4.1.311.21.13 : szOID_ARCHIVED_KEY_ATTR")
    OID_21_14_SZOID_CRL_SELF_CDP = ("1.3.6.1.4.1.311.21.14 : szOID_CRL_SELF_CDP")
    OID_21_15_SZOID_REQUIRE_CERT_CHAIN_POLICY = ("1.3.6.1.4.1.311.21.15 : szOID_REQUIRE_CERT_CHAIN_POLICY")
    OID_21_16_SZOID_ARCHIVED_KEY_CERT_HASH = ("1.3.6.1.4.1.311.21.16 : szOID_ARCHIVED_KEY_CERT_HASH")
    OID_21_17_SZOID_ISSUED_CERT_HASH = ("1.3.6.1.4.1.311.21.17 : szOID_ISSUED_CERT_HASH")
    OID_21_19_SZOID_DS_EMAIL_REPLICATION = ("1.3.6.1.4.1.311.21.19 : szOID_DS_EMAIL_REPLICATION")
    OID_21_20_SZOID_REQUEST_CLIENT_INFO = ("1.3.6.1.4.1.311.21.20 : szOID_REQUEST_CLIENT_INFO")
    OID_21_21_SZOID_ENCRYPTED_KEY_HASH = ("1.3.6.1.4.1.311.21.21 : szOID_ENCRYPTED_KEY_HASH")
    OID_21_22_SZOID_CERTSRV_CROSSCA_VERSION = ("1.3.6.1.4.1.311.21.22 : szOID_CERTSRV_CROSSCA_VERSION")
    OID_21_30_ENDORSEMENT_KEY_HIGH_ASSURANCE = ("1.3.6.1.4.1.311.21.30 : Endorsement Key High Assurance")
    OID_21_31_ENDORSEMENT_CERT_MEDIUM_ASSURANCE = ("1.3.6.1.4.1.311.21.31 : Endorsement Certificate Medium Assurance")
    OID_21_32_USER_CREDENTIALS_LOW_ASSURANCE = ("1.3.6.1.4.1.311.21.32 : User Credentials Low Assurance")

class PreAdmissionCriterionAttribute(str, Enum):
    USER_NAME = "User-Name"


class PreAdmissionAuth:
    ACCEPT = "vlan:\tIsCOA:false"
    REJECT_DUMMY = "reject=dummy"
