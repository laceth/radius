from framework.log.logger import log

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
    "enable sasl encryption for ldap bindings": "config.ldap_sign_and_seal.value",
}
# handles implicit options
implicit_field_mapping = {
    "config.ldap_ad_port.value": {
        "standard ldap": "389",
        "standard ldap over tls": "636",
        "global catalog": "3268",
        "global catalog over tls": "3269",
        "user directory plugin port per ad": "0",
    }
}


def configure_radius_plugin(conf_dict, ca):
    """
        Configure RADIUS plugin settings based on the provided configuration dictionary.
        ie. conf_dict = {
        "active directory port for ldap queries": "global catalog",
        "enable radsec": "true",
        "allow only radsec connections": "False",
        "counteract radius radsec port": 12345
    }
    """
    cmd_list = []
    log.info("Configuring RADIUS plugin settings")
    try:
        for key, val in conf_dict.items():
            if key.lower() not in radius_setting_option_mapping:
                valid_options = ", ".join(radius_setting_option_mapping.keys())
                raise Exception("Invalid configuration option: %s. Valid options are: %s" % (key, valid_options))
            key = radius_setting_option_mapping[key.lower()]
            if key.lower() in implicit_field_mapping:
                if val.lower() not in implicit_field_mapping[key.lower()]:
                    raise Exception("%s doesn't have a option for %s" % (key, val))
                val = implicit_field_mapping[key.lower()][val.lower()]
            cmd = "fstool dot1x set_property %s %s" % (key, str(val).lower())
            cmd_list.append(cmd)
            ca.exec_command(cmd)
    except Exception as e:
        log.error(f"Error configuring RADIUS plugin settings: {e}")
        raise e
    log.info("RADIUS plugin settings configured successfully")
    return cmd_list
