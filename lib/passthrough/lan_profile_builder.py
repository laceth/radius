"""
LAN Profile XML builder for Windows 802.1X NIC configuration.

Replaces hardcoded XML files with a parametrizable dataclass that generates
the XML on-the-fly. Supports EAP-TLS, PEAP/MSCHAPv2, PEAP/EAP-TLS, MAB, and
EAP-TTLS (PAP, CHAP, MS-CHAP, MS-CHAP v2, EAP-MSCHAPv2, EAP-TLS/cert) profiles.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString


# ============================================================================
# Namespaces
# ============================================================================
NS_LAN = "http://www.microsoft.com/networking/LAN/profile/v1"
NS_ONEX = "http://www.microsoft.com/networking/OneX/v1"
NS_EAPHOST = "http://www.microsoft.com/provisioning/EapHostConfig"
NS_EAPCOMMON = "http://www.microsoft.com/provisioning/EapCommon"
NS_BASEEAP = "http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"
NS_EAPTLS_V1 = "http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1"
NS_EAPTLS_V2 = "http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2"
NS_PEAP_V1 = "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1"
NS_PEAP_V2 = "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2"
NS_PEAP_V3 = "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV3"
NS_MSCHAPV2 = "http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"
NS_EAPTTLS_V1 = "http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1"

# Map namespace URIs to short prefixes for registration.
# ElementTree serialization will use these; _pretty() cleans up the output.
_NS_MAP = {
    "lan": NS_LAN,
    "onex": NS_ONEX,
    "eaphost": NS_EAPHOST,
    "eapcommon": NS_EAPCOMMON,
    "baseeap": NS_BASEEAP,
    "eaptls1": NS_EAPTLS_V1,
    "eaptls2": NS_EAPTLS_V2,
    "peap1": NS_PEAP_V1,
    "peap2": NS_PEAP_V2,
    "peap3": NS_PEAP_V3,
    "mschapv2": NS_MSCHAPV2,
    "eapttls1": NS_EAPTTLS_V1,
}
for _p, _u in _NS_MAP.items():
    ET.register_namespace(_p, _u)


class EapType(Enum):
    """EAP method types used in 802.1X profiles."""
    TLS = 13
    PEAP = 25
    MSCHAPV2 = 26
    TTLS = 21


class AuthMode(Enum):
    """Authentication mode for 802.1X."""
    MACHINE = "machine"
    USER = "user"
    MACHINE_OR_USER = "machineOrUser"


# ============================================================================
# EAP-TLS inner config
# ============================================================================
@dataclass
class EapTlsConfig:
    """Configuration for EAP-TLS authentication method."""
    simple_cert_selection: bool = True
    disable_user_prompt_for_server_validation: bool = False
    server_names: str = ""
    trusted_root_ca: Optional[str] = "fb b8 8c 61 b9 2b 92 8e 24 a3 bf 72 21 95 74 e3 ef 12 cb e1"
    different_username: bool = False
    perform_server_validation: bool = True
    accept_server_name: bool = False

    def build(self, parent: Element):
        """Build EAP-TLS XML under parent <Eap> element."""
        eap = SubElement(parent, f"{{{NS_BASEEAP}}}Eap")
        SubElement(eap, f"{{{NS_BASEEAP}}}Type").text = str(EapType.TLS.value)

        eap_type = SubElement(eap, f"{{{NS_EAPTLS_V1}}}EapType")

        cred = SubElement(eap_type, f"{{{NS_EAPTLS_V1}}}CredentialsSource")
        store = SubElement(cred, f"{{{NS_EAPTLS_V1}}}CertificateStore")
        SubElement(store, f"{{{NS_EAPTLS_V1}}}SimpleCertSelection").text = _bool(self.simple_cert_selection)

        sv = SubElement(eap_type, f"{{{NS_EAPTLS_V1}}}ServerValidation")
        SubElement(sv, f"{{{NS_EAPTLS_V1}}}DisableUserPromptForServerValidation").text = _bool(
            self.disable_user_prompt_for_server_validation
        )
        SubElement(sv, f"{{{NS_EAPTLS_V1}}}ServerNames").text = self.server_names or None
        if self.trusted_root_ca:
            SubElement(sv, f"{{{NS_EAPTLS_V1}}}TrustedRootCA").text = self.trusted_root_ca

        SubElement(eap_type, f"{{{NS_EAPTLS_V1}}}DifferentUsername").text = _bool(self.different_username)
        SubElement(eap_type, f"{{{NS_EAPTLS_V2}}}PerformServerValidation").text = _bool(
            self.perform_server_validation
        )
        SubElement(eap_type, f"{{{NS_EAPTLS_V2}}}AcceptServerName").text = _bool(self.accept_server_name)


@dataclass
class MsChapV2Config:
    """Inner EAP-MSCHAPv2 configuration (used as inner method in EAP-TTLS)."""
    use_win_logon_credentials: bool = False

    def build(self, parent: Element):
        """Build MSCHAPv2 <Eap> block under parent <Config> element."""
        eap = SubElement(parent, f"{{{NS_BASEEAP}}}Eap")
        SubElement(eap, f"{{{NS_BASEEAP}}}Type").text = str(EapType.MSCHAPV2.value)
        eap_type = SubElement(eap, f"{{{NS_MSCHAPV2}}}EapType")
        SubElement(eap_type, f"{{{NS_MSCHAPV2}}}UseWinLogonCredentials").text = _bool(
            self.use_win_logon_credentials
        )


# ============================================================================
# PEAP inner config
# ============================================================================
@dataclass
class PeapMsChapV2Config:
    """Configuration for PEAP with MSCHAPv2 inner method."""
    use_win_logon_credentials: bool = False
    disable_user_prompt_for_server_validation: bool = False
    server_names: str = ""
    fast_reconnect: bool = True
    inner_eap_optional: bool = False
    enable_quarantine_checks: bool = False
    require_crypto_binding: bool = False
    perform_server_validation: bool = False
    accept_server_name: bool = False
    allow_prompting_when_server_ca_not_found: bool = True
    enable_identity_privacy: bool = False
    anonymous_username: str = ""

    def build(self, parent: Element):
        """Build PEAP/MSCHAPv2 XML under parent <Eap> element."""
        eap = SubElement(parent, f"{{{NS_BASEEAP}}}Eap")
        SubElement(eap, f"{{{NS_BASEEAP}}}Type").text = str(EapType.PEAP.value)

        eap_type = SubElement(eap, f"{{{NS_PEAP_V1}}}EapType")

        sv = SubElement(eap_type, f"{{{NS_PEAP_V1}}}ServerValidation")
        SubElement(sv, f"{{{NS_PEAP_V1}}}DisableUserPromptForServerValidation").text = _bool(
            self.disable_user_prompt_for_server_validation
        )
        SubElement(sv, f"{{{NS_PEAP_V1}}}ServerNames").text = self.server_names or None

        SubElement(eap_type, f"{{{NS_PEAP_V1}}}FastReconnect").text = _bool(self.fast_reconnect)
        SubElement(eap_type, f"{{{NS_PEAP_V1}}}InnerEapOptional").text = _bool(self.inner_eap_optional)

        # Inner EAP: MSCHAPv2
        inner_eap = SubElement(eap_type, f"{{{NS_BASEEAP}}}Eap")
        SubElement(inner_eap, f"{{{NS_BASEEAP}}}Type").text = str(EapType.MSCHAPV2.value)
        inner_eap_type = SubElement(inner_eap, f"{{{NS_MSCHAPV2}}}EapType")
        SubElement(inner_eap_type, f"{{{NS_MSCHAPV2}}}UseWinLogonCredentials").text = _bool(
            self.use_win_logon_credentials
        )

        SubElement(eap_type, f"{{{NS_PEAP_V1}}}EnableQuarantineChecks").text = _bool(self.enable_quarantine_checks)
        SubElement(eap_type, f"{{{NS_PEAP_V1}}}RequireCryptoBinding").text = _bool(self.require_crypto_binding)

        # PEAP extensions
        ext = SubElement(eap_type, f"{{{NS_PEAP_V1}}}PeapExtensions")
        SubElement(ext, f"{{{NS_PEAP_V2}}}PerformServerValidation").text = _bool(self.perform_server_validation)
        SubElement(ext, f"{{{NS_PEAP_V2}}}AcceptServerName").text = _bool(self.accept_server_name)

        ext_v2 = SubElement(ext, f"{{{NS_PEAP_V2}}}PeapExtensionsV2")
        SubElement(ext_v2, f"{{{NS_PEAP_V3}}}AllowPromptingWhenServerCANotFound").text = _bool(
            self.allow_prompting_when_server_ca_not_found
        )

        # Identity Privacy (v2 extension)
        if self.enable_identity_privacy:
            id_priv = SubElement(eap_type, f"{{{NS_PEAP_V2}}}IdentityPrivacy")
            SubElement(id_priv, f"{{{NS_PEAP_V2}}}EnableIdentityPrivacy").text = "true"
            SubElement(id_priv, f"{{{NS_PEAP_V2}}}AnonymousUserName").text = self.anonymous_username


@dataclass
class PeapEapTlsConfig:
    """Configuration for PEAP with inner EAP-TLS method."""
    inner_tls: EapTlsConfig = field(default_factory=EapTlsConfig)
    disable_user_prompt_for_server_validation: bool = False
    server_names: str = ""
    fast_reconnect: bool = True
    inner_eap_optional: bool = False
    enable_quarantine_checks: bool = False
    require_crypto_binding: bool = False
    perform_server_validation: bool = False
    accept_server_name: bool = False
    allow_prompting_when_server_ca_not_found: bool = True

    def build(self, parent: Element):
        """Build PEAP/EAP-TLS XML under parent <Eap> element."""
        eap = SubElement(parent, f"{{{NS_BASEEAP}}}Eap")
        SubElement(eap, f"{{{NS_BASEEAP}}}Type").text = str(EapType.PEAP.value)

        eap_type = SubElement(eap, f"{{{NS_PEAP_V1}}}EapType")

        sv = SubElement(eap_type, f"{{{NS_PEAP_V1}}}ServerValidation")
        SubElement(sv, f"{{{NS_PEAP_V1}}}DisableUserPromptForServerValidation").text = _bool(
            self.disable_user_prompt_for_server_validation
        )
        SubElement(sv, f"{{{NS_PEAP_V1}}}ServerNames").text = self.server_names or None

        SubElement(eap_type, f"{{{NS_PEAP_V1}}}FastReconnect").text = _bool(self.fast_reconnect)
        SubElement(eap_type, f"{{{NS_PEAP_V1}}}InnerEapOptional").text = _bool(self.inner_eap_optional)

        # Inner EAP: EAP-TLS
        self.inner_tls.build(eap_type)

        SubElement(eap_type, f"{{{NS_PEAP_V1}}}EnableQuarantineChecks").text = _bool(self.enable_quarantine_checks)
        SubElement(eap_type, f"{{{NS_PEAP_V1}}}RequireCryptoBinding").text = _bool(self.require_crypto_binding)

        ext = SubElement(eap_type, f"{{{NS_PEAP_V1}}}PeapExtensions")
        SubElement(ext, f"{{{NS_PEAP_V2}}}PerformServerValidation").text = _bool(self.perform_server_validation)
        SubElement(ext, f"{{{NS_PEAP_V2}}}AcceptServerName").text = _bool(self.accept_server_name)

        ext_v2 = SubElement(ext, f"{{{NS_PEAP_V2}}}PeapExtensionsV2")
        SubElement(ext_v2, f"{{{NS_PEAP_V3}}}AllowPromptingWhenServerCANotFound").text = _bool(
            self.allow_prompting_when_server_ca_not_found
        )


# ============================================================================
# EAP-TTLS: inner method classes + unified outer config
# ============================================================================

def _build_inner_eap_host_config(parent: Element, eap_type_val: int, author_id: int = 0) -> Element:
    """Build a nested EapHostConfig+EapMethod block; returns the Config element for the caller to populate."""
    inner_host = SubElement(parent, "EapHostConfig", xmlns=NS_EAPHOST)
    inner_method = SubElement(inner_host, "EapMethod")
    SubElement(inner_method, "Type", xmlns=NS_EAPCOMMON).text = str(eap_type_val)
    SubElement(inner_method, "VendorId", xmlns=NS_EAPCOMMON).text = "0"
    SubElement(inner_method, "VendorType", xmlns=NS_EAPCOMMON).text = "0"
    SubElement(inner_method, "AuthorId", xmlns=NS_EAPCOMMON).text = str(author_id)
    return SubElement(inner_host, "Config", xmlns=NS_EAPHOST)


# ---------------------------------------------------------------------------
# Non-EAP inner methods  (Phase2Authentication → single element / simple block)
# ---------------------------------------------------------------------------

@dataclass
class TtlsInnerPap:
    """Non-EAP inner method: PAP.
    Windows XML: <PAPAuthentication/>
    """
    default_auth_mode = AuthMode.USER  # class var — read by LanProfile.eap_ttls()

    def build_phase2(self, phase2: Element):
        SubElement(phase2, f"{{{NS_EAPTTLS_V1}}}PAPAuthentication")


@dataclass
class TtlsInnerChap:
    """Non-EAP inner method: CHAP.
    Windows XML: <CHAPAuthentication/>
    """
    default_auth_mode = AuthMode.USER

    def build_phase2(self, phase2: Element):
        SubElement(phase2, f"{{{NS_EAPTTLS_V1}}}CHAPAuthentication")


@dataclass
class TtlsInnerMsChap:
    """Non-EAP inner method: MS-CHAP v1.
    Windows XML: <MSCHAPAuthentication/>
    """
    default_auth_mode = AuthMode.USER

    def build_phase2(self, phase2: Element):
        SubElement(phase2, f"{{{NS_EAPTTLS_V1}}}MSCHAPAuthentication")


@dataclass
class TtlsInnerMsChapV2:
    """Non-EAP inner method: MS-CHAP v2 (no EAP framing).
    Distinct from TtlsInnerEapMsChapV2 which wraps MSCHAPv2 inside EAP (Type=26).
    Windows XML: <MSCHAPv2Authentication><UseWinlogonCredentials>false</...>
    Note: element is UseWinlogonCredentials (lowercase 'l') vs the EAP variant UseWinLogonCredentials.
    """
    use_winlogon_credentials: bool = False
    default_auth_mode = AuthMode.USER

    def build_phase2(self, phase2: Element):
        el = SubElement(phase2, f"{{{NS_EAPTTLS_V1}}}MSCHAPv2Authentication")
        SubElement(el, f"{{{NS_EAPTTLS_V1}}}UseWinlogonCredentials").text = _bool(
            self.use_winlogon_credentials
        )


# ---------------------------------------------------------------------------
# EAP inner methods  (Phase2Authentication → full EapHostConfig block)
# ---------------------------------------------------------------------------

@dataclass
class TtlsInnerEapMsChapV2:
    """EAP inner method: EAP-MSCHAPv2 (MSCHAPv2 wrapped in EAP framing, Type=26).
    Distinct from TtlsInnerMsChapV2 which sends MSCHAPv2 directly without EAP.
    Windows XML: Phase2Authentication → EapHostConfig(Type=26) → <Eap><Type>26 ...
    Note: element is UseWinLogonCredentials (capital 'L') vs the non-EAP variant.
    """
    inner_mschapv2: MsChapV2Config = field(default_factory=MsChapV2Config)
    default_auth_mode = AuthMode.USER

    def build_phase2(self, phase2: Element):
        inner_config = _build_inner_eap_host_config(phase2, EapType.MSCHAPV2.value, author_id=0)
        self.inner_mschapv2.build(inner_config)


@dataclass
class TtlsInnerEapTls:
    """EAP inner method: EAP-TLS (certificate-based, Type=13). Computer authentication.
    Windows XML: Phase2Authentication → EapHostConfig(Type=13) → <Eap><Type>13 ...
    """
    inner_tls: EapTlsConfig = field(default_factory=EapTlsConfig)
    default_auth_mode = AuthMode.MACHINE

    def build_phase2(self, phase2: Element):
        inner_config = _build_inner_eap_host_config(phase2, EapType.TLS.value, author_id=0)
        self.inner_tls.build(inner_config)


# ---------------------------------------------------------------------------
# Unified EAP-TTLS outer config
# ---------------------------------------------------------------------------

@dataclass
class EapTtlsConfig:
    """
    Unified EAP-TTLS outer configuration with a pluggable inner method.

    Supported inner methods:
        Non-EAP:  TtlsInnerPap, TtlsInnerChap, TtlsInnerMsChap, TtlsInnerMsChapV2
        EAP:      TtlsInnerEapMsChapV2, TtlsInnerEapTls

    Example:
        EapTtlsConfig(inner=TtlsInnerPap())
        EapTtlsConfig(inner=TtlsInnerEapMsChapV2())
        EapTtlsConfig(inner=TtlsInnerEapTls())
    """
    inner: Union[
        TtlsInnerPap, TtlsInnerChap, TtlsInnerMsChap, TtlsInnerMsChapV2,
        TtlsInnerEapMsChapV2, TtlsInnerEapTls,
    ] = field(default_factory=TtlsInnerEapMsChapV2)
    disable_user_prompt_for_server_validation: bool = False
    server_names: str = ""
    trusted_root_ca: Optional[str] = "fb b8 8c 61 b9 2b 92 8e 24 a3 bf 72 21 95 74 e3 ef 12 cb e1"
    enable_identity_privacy: bool = False

    def build(self, parent: Element):
        """Build EAP-TTLS XML under parent <Config> element."""
        ttls = SubElement(parent, f"{{{NS_EAPTTLS_V1}}}EapTtls")

        sv = SubElement(ttls, f"{{{NS_EAPTTLS_V1}}}ServerValidation")
        SubElement(sv, f"{{{NS_EAPTTLS_V1}}}ServerNames").text = self.server_names or None
        if self.trusted_root_ca:
            SubElement(sv, f"{{{NS_EAPTTLS_V1}}}TrustedRootCAHash").text = self.trusted_root_ca
        SubElement(sv, f"{{{NS_EAPTTLS_V1}}}DisablePrompt").text = _bool(
            self.disable_user_prompt_for_server_validation
        )

        phase2 = SubElement(ttls, f"{{{NS_EAPTTLS_V1}}}Phase2Authentication")
        self.inner.build_phase2(phase2)

        phase1 = SubElement(ttls, f"{{{NS_EAPTTLS_V1}}}Phase1Identity")
        SubElement(phase1, f"{{{NS_EAPTTLS_V1}}}IdentityPrivacy").text = _bool(self.enable_identity_privacy)


# ============================================================================
# Top-level LAN profile
# ============================================================================
@dataclass
class LanProfile:
    """
    Windows LAN profile for 802.1X NIC configuration.

    Generates the XML that ``netsh lan add profile`` consumes.

    Usage:
        # EAP-TLS (defaults)
        profile = LanProfile.eap_tls()
        xml_str = profile.to_xml()

        # PEAP/MSCHAPv2
        profile = LanProfile.peap()
        xml_str = profile.to_xml()

        # PEAP with identity privacy
        profile = LanProfile.peap(
            eap_config=PeapMsChapV2Config(
                enable_identity_privacy=True,
                anonymous_username="anonymous"
            )
        )

        # MAB (802.1X disabled)
        profile = LanProfile.mab()

        # EAP-TTLS (generic factory — inner method is explicit):
        profile = LanProfile.eap_ttls(inner=TtlsInnerEapMsChapV2())

        # EAP-TTLS convenience factories:
        profile = LanProfile.eap_ttls_eap_cert()           # EAP inner: EAP-TLS / certificate (computer)
        profile = LanProfile.eap_ttls_eap_mschapv2()       # EAP inner: EAP-MSCHAPv2 (user)
        profile = LanProfile.eap_ttls_non_eap_pap()        # non-EAP: PAP (user)
        profile = LanProfile.eap_ttls_non_eap_chap()       # non-EAP: CHAP (user)
        profile = LanProfile.eap_ttls_non_eap_mschap()     # non-EAP: MS-CHAP v1 (user)
        profile = LanProfile.eap_ttls_non_eap_mschapv2()   # non-EAP: MS-CHAP v2 (user)

        # Fully custom
        profile = LanProfile(
            onex_enabled=True,
            auth_mode=AuthMode.USER,
            eap_method=EapType.PEAP,
            eap_config=PeapMsChapV2Config(use_win_logon_credentials=False),
        )
    """
    onex_enforced: bool = True
    onex_enabled: bool = True
    cache_user_data: bool = False
    auth_mode: AuthMode = AuthMode.MACHINE
    eap_method: Optional[EapType] = EapType.TLS
    eap_config: Optional[Union[EapTlsConfig, MsChapV2Config, PeapMsChapV2Config, PeapEapTlsConfig, EapTtlsConfig]] = field(default_factory=EapTlsConfig)
    author_id: int = 0  # 0 for EAP-TLS/PEAP, 311 for EAP-TTLS (Microsoft built-in)

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------
    @classmethod
    def eap_tls(cls, **overrides) -> "LanProfile":
        """Create EAP-TLS profile with sensible defaults."""
        tls_config = overrides.pop("eap_config", EapTlsConfig())
        return cls(
            onex_enforced=True,
            onex_enabled=True,
            auth_mode=AuthMode.MACHINE,
            eap_method=EapType.TLS,
            eap_config=tls_config,
            **overrides,
        )

    @classmethod
    def peap(cls, **overrides) -> "LanProfile":
        """Create PEAP/MSCHAPv2 profile with sensible defaults."""
        peap_config = overrides.pop("eap_config", PeapMsChapV2Config())
        return cls(
            onex_enforced=True,
            onex_enabled=True,
            auth_mode=AuthMode.USER,
            eap_method=EapType.PEAP,
            eap_config=peap_config,
            **overrides,
        )

    @classmethod
    def peap_eap_tls(cls, **overrides) -> "LanProfile":
        """Create PEAP/EAP-TLS profile with sensible defaults."""
        peap_tls_config = overrides.pop("eap_config", PeapEapTlsConfig())
        return cls(
            onex_enforced=True,
            onex_enabled=True,
            auth_mode=AuthMode.MACHINE,
            eap_method=EapType.PEAP,
            eap_config=peap_tls_config,
            **overrides,
        )

    @classmethod
    def mab(cls) -> "LanProfile":
        """Create MAB profile (802.1X disabled)."""
        return cls(
            onex_enforced=False,
            onex_enabled=False,
            eap_method=None,
            eap_config=None,
        )

    @classmethod
    def eap_ttls(cls, inner=None, **overrides) -> "LanProfile":
        """Generic EAP-TTLS factory. Auth mode is inferred from the inner method.

        Args:
            inner: An inner method instance. Defaults to TtlsInnerEapMsChapV2().
            **overrides: Any LanProfile field can be overridden (e.g. auth_mode).

        Example:
            LanProfile.eap_ttls(inner=TtlsInnerPap())
            LanProfile.eap_ttls(inner=TtlsInnerEapTls())
        """
        if inner is None:
            inner = TtlsInnerEapMsChapV2()
        ttls_config = overrides.pop("eap_config", EapTtlsConfig(inner=inner))
        auth_mode = overrides.pop("auth_mode", inner.default_auth_mode)
        return cls(
            onex_enforced=True,
            onex_enabled=True,
            auth_mode=auth_mode,
            eap_method=EapType.TTLS,
            eap_config=ttls_config,
            author_id=311,
            **overrides,
        )

    @classmethod
    def eap_ttls_eap_cert(cls, **overrides) -> "LanProfile":
        """EAP-TTLS with inner EAP-TLS (certificate). Computer authentication."""
        return cls.eap_ttls(inner=TtlsInnerEapTls(), **overrides)

    @classmethod
    def eap_ttls_eap_mschapv2(cls, **overrides) -> "LanProfile":
        """EAP-TTLS with inner EAP-MSCHAPv2 (EAP-framed). User authentication."""
        return cls.eap_ttls(inner=TtlsInnerEapMsChapV2(), **overrides)

    @classmethod
    def eap_ttls_non_eap_pap(cls, **overrides) -> "LanProfile":
        """EAP-TTLS with non-EAP PAP. User authentication."""
        return cls.eap_ttls(inner=TtlsInnerPap(), **overrides)

    @classmethod
    def eap_ttls_non_eap_chap(cls, **overrides) -> "LanProfile":
        """EAP-TTLS with non-EAP CHAP. User authentication."""
        return cls.eap_ttls(inner=TtlsInnerChap(), **overrides)

    @classmethod
    def eap_ttls_non_eap_mschap(cls, **overrides) -> "LanProfile":
        """EAP-TTLS with non-EAP MS-CHAP v1. User authentication."""
        return cls.eap_ttls(inner=TtlsInnerMsChap(), **overrides)

    @classmethod
    def eap_ttls_non_eap_mschapv2(cls, **overrides) -> "LanProfile":
        """EAP-TTLS with non-EAP MS-CHAP v2 (no EAP framing). User authentication."""
        return cls.eap_ttls(inner=TtlsInnerMsChapV2(), **overrides)

    # ------------------------------------------------------------------
    # XML generation
    # ------------------------------------------------------------------
    def to_xml(self) -> str:
        """
        Build the LAN profile XML string.

        Returns:
            Pretty-printed XML string ready for ``netsh lan add profile``.
        """
        root = Element("LANProfile", xmlns=NS_LAN)
        msm = SubElement(root, "MSM")
        security = SubElement(msm, "security")
        SubElement(security, "OneXEnforced").text = _bool(self.onex_enforced)
        SubElement(security, "OneXEnabled").text = _bool(self.onex_enabled)

        if not self.onex_enabled or self.eap_method is None:
            return _pretty(root)

        onex = SubElement(security, "OneX", xmlns=NS_ONEX)
        SubElement(onex, "cacheUserData").text = _bool(self.cache_user_data)
        SubElement(onex, "authMode").text = self.auth_mode.value

        eap_config_el = SubElement(onex, "EAPConfig")
        eap_host = SubElement(eap_config_el, "EapHostConfig", xmlns=NS_EAPHOST)

        # EapMethod block
        eap_method_el = SubElement(eap_host, "EapMethod")
        SubElement(eap_method_el, "Type", xmlns=NS_EAPCOMMON).text = str(self.eap_method.value)
        SubElement(eap_method_el, "VendorId", xmlns=NS_EAPCOMMON).text = "0"
        SubElement(eap_method_el, "VendorType", xmlns=NS_EAPCOMMON).text = "0"
        SubElement(eap_method_el, "AuthorId", xmlns=NS_EAPCOMMON).text = str(self.author_id)

        # Config block — delegates to the specific EAP config dataclass
        config_el = SubElement(eap_host, "Config", xmlns=NS_EAPHOST)
        if self.eap_config is not None:
            self.eap_config.build(config_el)

        return _pretty(root)

    def write(self, path: str):
        """Write profile XML to a file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_xml())


# ============================================================================
# Helpers
# ============================================================================
def _bool(val: bool) -> str:
    return "true" if val else "false"


def _pretty(root: Element) -> str:
    """
    Return pretty-printed XML without the XML declaration.

    Converts ElementTree's ``prefix:Tag`` notation into inline ``xmlns=``
    attributes on each element, then strips redundant xmlns= declarations
    from child elements that inherit the same namespace from their parent.
    Matches the format Windows ``netsh lan`` expects.
    """
    import re as _re

    raw = tostring(root, encoding="unicode")

    # Use the namespace map (prefix -> URI) to inline namespaces into elements

    # Replace <prefix:Tag … > with <Tag xmlns="…" … > and </prefix:Tag> with </Tag>
    for prefix, uri in _NS_MAP.items():
        raw = _re.sub(
            rf'<{prefix}:(\w+)',
            rf'<\1 xmlns="{uri}"',
            raw,
        )
        raw = raw.replace(f"</{prefix}:", "</")
        raw = raw.replace(f' xmlns:{prefix}="{uri}"', "")

    # Remove duplicate xmlns on the same element (keep first occurrence)
    def _dedup_xmlns(match: _re.Match) -> str:
        tag_text = match.group(0)
        seen = set()
        parts = []
        for part in _re.split(r'( xmlns="[^"]*")', tag_text):
            if part.startswith(' xmlns="'):
                if part in seen:
                    continue
                seen.add(part)
            parts.append(part)
        return "".join(parts)

    raw = _re.sub(r'<[^>]+>', _dedup_xmlns, raw)

    # Parse into DOM for pretty-printing
    dom = parseString(raw)

    # Strip redundant xmlns: remove xmlns from child elements when their
    # parent already declares the same namespace (children inherit it).
    def _strip_inherited_xmlns(node, inherited_ns=None):
        if node.nodeType == node.ELEMENT_NODE:
            declared_ns = node.getAttribute("xmlns")
            effective_ns = declared_ns or inherited_ns
            # If this element explicitly declares the same namespace as its parent, remove it
            if declared_ns and declared_ns == inherited_ns:
                node.removeAttribute("xmlns")
            for child in list(node.childNodes):
                _strip_inherited_xmlns(child, effective_ns)

    _strip_inherited_xmlns(dom.documentElement)

    lines = dom.toprettyxml(indent="  ").split("\n")
    return "\n".join(line for line in lines if not line.startswith("<?xml") and line.strip())
