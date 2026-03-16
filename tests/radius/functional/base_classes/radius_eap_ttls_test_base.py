"""
Base class for EAP-TTLS RADIUS authentication tests.
EAP-TTLS supports six inner-method variants -- all share the same outer TTLS tunnel
but differ in how the client proves identity inside:
  Variant                  NIC Profile factory                      Auth style
  ---------                -----------------------                  ----------
  Certificate (EAP)        LanProfile.eap_ttls_eap_cert()           Computer / cert
  EAP-MSCHAPv2 (EAP)       LanProfile.eap_ttls_eap_mschapv2()       User / password  
  PAP (non-EAP)            LanProfile.eap_ttls_non_eap_pap()        User / password
  CHAP (non-EAP)           LanProfile.eap_ttls_non_eap_chap()       User / password
  MS-CHAP v1 (non-EAP)     LanProfile.eap_ttls_non_eap_mschap()     User / password
  MS-CHAP v2 (non-EAP)     LanProfile.eap_ttls_non_eap_mschapv2()   User / password

Design -- multiple inheritance:
    RadiusEapTtlsTestBase
        +-- RadiusCertificatesTestBase   (cert import/removal, configure_lan_profile)
        +-- RadiusPeapTestBase           (setup_peap_credentials, download_psexec, PS helpers)
              +-- RadiusTestBase         (switch, CA, toggle_nic, log collectors)
    do_setup() chain:
        RadiusCertificatesTestBase.do_setup() -- cleanup_all_test_certificates
        -> RadiusPeapTestBase.do_setup()    -- download_psexec
            -> RadiusTestBase.do_setup()    -- log collectors, endpoint cleanup, switch config
"""

from typing import Union
from framework.log.logger import log
from lib.passthrough.enums import WindowsCert
from lib.plugin.radius.enums import RadiusAuthStatus
from tests.radius.functional.base_classes.radius_certificates_test_base import RadiusCertificatesTestBase
from tests.radius.functional.base_classes.radius_peap_test_base import RadiusPeapTestBase


class RadiusEapTtlsTestBase(RadiusCertificatesTestBase, RadiusPeapTestBase):

    DEFAULT_EAP_TYPE = "EAP-TTLS"

    def do_setup(self):
        """Setup phase: run common setup and import the outer-tunnel root certificate.

        EAP-TTLS always establishes a TLS outer tunnel regardless of inner method,
        so the RADIUS server's CA certificate must be trusted on the endpoint for
        all variants (password-based and cert-based alike).
        """
        super().do_setup()

        # Import outer-tunnel root certificate (required by all EAP-TTLS variants)
        log.info("Importing outer-tunnel root certificate for EAP-TTLS")
        self.cert_config.certificate_filename = WindowsCert.CERT_DOT1X_EKU_G.value
        self.import_certificates(certificate_password='aristo')

    # ==================================================================
    # setup_eap_ttls_credentials -- password-based inner methods
    # (EAP-MSCHAPv2, PAP, CHAP, MS-CHAP, MS-CHAP v2)
    # ==================================================================

    def setup_eap_ttls_credentials(
        self,
        domain: str = "txqalab",
        username: str = "dotonex",
        password: str = "aristo",
    ):
        """
        Configure EAP-TTLS username/password credentials on the Windows NIC.

        Delegates to setup_peap_credentials() from RadiusPeapTestBase.
        The PEAP PowerShell script writes 802.1X credentials (user + password)
        onto the NIC; the profile XML loaded by configure_lan_profile() determines
        that the outer method on the wire is EAP-TTLS, not PEAP.

        Args:
            domain:   Domain name, or "" for username-only format (no domain prefix).
            username: Authentication username.
            password: Authentication password (default: 'aristo').
        """
        prefix = domain + "\\" + username if domain else username
        log.info(f"Setting up EAP-TTLS credentials for: {prefix}")
        self.setup_peap_credentials(domain, username, password)

    # ==================================================================
    # Authentication Verification
    # ==================================================================

    def verify_authentication_on_ca(
        self,
        switch_ip: str = None,
        ca_ip: str = None,
        auth_status: Union[RadiusAuthStatus, str] = RadiusAuthStatus.ACCESS_ACCEPT,
        inner_method: str = "eap_mschapv2",
        **kwargs,
    ):
        """
        Verify EAP-TTLS authentication properties on CounterAct.

        Routes to the correct parent verifier based on inner_method:
          - Password-based (EAP or non-EAP) → RadiusPeapTestBase.verify_authentication_on_ca
                                               with eap_type="TTLS"
            Accepted values: "eap_mschapv2", "pap", "chap", "mschap", "mschapv2"
          - Certificate (EAP-TLS)           → RadiusCertificatesTestBase.verify_authentication_on_ca
                                               with eap_type="TTLS"
            Accepted values: "cert"

        Args:
            switch_ip:    Expected dot1x_NAS_addr. Defaults to self.switch.ip.
            ca_ip:        Expected dot1x_auth_appliance. Defaults to self.ca.ipaddress.
            auth_status:  Expected authentication status.
            inner_method: EAP-TTLS inner authentication method. One of:
                            "eap_mschapv2" -- EAP-MSCHAPv2 (EAP-framed, default)
                            "eap_cert"     -- EAP-TLS / certificate (EAP)
                            "pap"          -- PAP (non-EAP)
                            "chap"         -- CHAP (non-EAP)
                            "mschap"       -- MS-CHAP v1 (non-EAP)
                            "mschapv2"     -- MS-CHAP v2 (non-EAP, no EAP framing)
            **kwargs:     Extra keyword arguments forwarded to the parent method.
                          For "cert": login_type, certificate_name are supported.
        """
        if inner_method in ("eap_mschapv2", "pap", "chap", "mschap", "mschapv2"):
            RadiusPeapTestBase.verify_authentication_on_ca(
                self,
                switch_ip=switch_ip,
                ca_ip=ca_ip,
                auth_status=auth_status,
                eap_type="TTLS",
                **kwargs,
            )
        elif inner_method == "eap_cert":
            RadiusCertificatesTestBase.verify_authentication_on_ca(
                self,
                switch_ip=switch_ip,
                ca_ip=ca_ip,
                auth_status=auth_status,
                eap_type="TTLS",
                **kwargs,
            )
        else:
            raise ValueError(
                f"Unknown EAP-TTLS inner_method: {inner_method!r}. "
                f"Expected one of: 'eap_mschapv2', 'cert', 'pap', 'chap', 'mschap', 'mschapv2'."
            )
