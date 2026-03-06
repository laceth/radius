from dataclasses import dataclass
from typing import Optional



@dataclass
class RadiusPluginSettings:
    """RADIUS plugin configuration settings dataclass."""

    # RADIUS Server Basic Settings
    counteract_radius_logging: str = "true"
    counteract_radius_authentication_port: str = "1812"
    counteract_radius_accounting_port: str = "1813"
    active_directory_port_for_ldap_queries: str = "standard ldap over tls"
    minimum_tls_version: str = "v1_2"
    fragment_size: str = "1024"

    # RadSec
    enable_radsec: str = "false"
    allow_only_radsec_connections: str = "false"
    counteract_radius_radsec_port: str = "2083"

    # RADIUS OCSP Settings
    enable_ocsp_freeradius: str = "false"
    enable_ocsp_openssl: str = "false"
    ocsp_certificate_name: Optional[str] = None
    override_certificate_ocsp_url: str = "false"
    ocsp_responder_url: Optional[str] = None
    ocsp_use_nonce: str = "true"
    soft_fail_ocsp_requests: str = "false"

    # RADIUS CRL Settings
    enable_crl: str = "false"
    additional_cdps: Optional[str] = None
    crl_update_frequency_hours: str = "12"

    # RADIUS Advanced Settings
    enable_fast_reauthentication_cache: str = "false"
    enable_pap_authentication: str = "false"
    enable_kerberos_authentication: str = "true"
    authenticate_using_machine_trust_account: str = "true"
    enable_sasl_encryption: str = "false"

    def to_dict(self) -> dict:
        """Convert to dictionary with original key names for configure_radius_plugin()."""
        return {
            "counteract radius logging": self.counteract_radius_logging,
            "counteract radius authentication port": self.counteract_radius_authentication_port,
            "counteract radius accounting port": self.counteract_radius_accounting_port,
            "active directory port for ldap queries": self.active_directory_port_for_ldap_queries,
            "minimum tls version": self.minimum_tls_version,
            "fragment size": self.fragment_size,
            "enable radsec": self.enable_radsec,
            "allow only radsec connections": self.allow_only_radsec_connections,
            "counteract radius radsec port": self.counteract_radius_radsec_port,
            "enable ocsp using freeradius built-in support for ocsp responder": self.enable_ocsp_freeradius,
            "enable ocsp using openssl shell support for ocsp responder": self.enable_ocsp_openssl,
            "ocsp certificate name": self.ocsp_certificate_name,
            "override certificate ocsp url": self.override_certificate_ocsp_url,
            "ocsp responder url": self.ocsp_responder_url,
            "ocsp use nonce": self.ocsp_use_nonce,
            "soft-fail ocsp requests": self.soft_fail_ocsp_requests,
            "enable crl": self.enable_crl,
            "additional cdps (optional)": self.additional_cdps,
            "crl update frequency (hours)": self.crl_update_frequency_hours,
            "enable fast-reauthentication cache": self.enable_fast_reauthentication_cache,
            "enable pap-authentication (username and password only)": self.enable_pap_authentication,
            "enable kerberos authentication for ldap queries": self.enable_kerberos_authentication,
            "authenticate using machine trust account (requires kerberos)": self.authenticate_using_machine_trust_account,
            "enable sasl encryption for ldap bindings": self.enable_sasl_encryption,
        }


radius_setting_option_mapping = {
    "counteract radius logging": "config.localradiusdebug.value",
    "counteract radius authentication port": "config.localradiusport.value",
    "counteract radius accounting port": "config.localacctport.value",
    "enable radsec": "config.enableradsec.value",
    "allow only radsec connections": "config.onlyradsec.value",
    "counteract radius radsec port": "config.radsecport.value",
    "active directory port for ldap queries": "config.ldap_ad_port.value",
    "minimum tls version": "config.min_tls_version.value",
    "fragment size": "config.fragment_size.value",
    "enable ocsp using freeradius built-in support for ocsp responder": "config.ocsp.value",
    "enable ocsp using openssl shell support for ocsp responder": "config.ocsp_shell.value",
    "ocsp certificate name": "config.ocsp_crt_name.value",
    "override certificate ocsp url": "config.ocsp_override.value",
    "ocsp responder url": "config.ocsp_url.value",
    "ocsp use nonce": "config.ocsp_nonce.value",
    "soft-fail ocsp requests": "config.ocsp_soft.value",
    "enable crl": "config.crl.value",
    "additional cdps (optional)": "config.crl_url.value",
    "crl update frequency (hours)": "config.crl_download_freq_number.value",
    "enable fast-reauthentication cache": "config.cache.value",
    "enable pap-authentication (username and password only)": "config.enable_pap_authentication.value",
    "enable kerberos authentication for ldap queries": "config.ldap_use_krb5.value",
    "authenticate using machine trust account (requires kerberos)": "config.ldap_use_machine_account.value",
    "enable sasl encryption for ldap bindings": "config.ldap_sign_and_seal.value"
}
# handles implicit options
implicit_field_mapping = {
    "config.ldap_ad_port.value": {
        "standard ldap": "389",
        "standard ldap over tls": "636",
        "global catalog": "3268",
        "global catalog over tls": "3269",
        "user directory plugin port per ad": "0"
    }
}

