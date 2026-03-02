"""
LAN Profile XML builder for Windows 802.1X NIC configuration.

Replaces hardcoded XML files with a parametrizable dataclass that generates
the XML on-the-fly. Supports EAP-TLS, PEAP/MSCHAPv2, PEAP/EAP-TLS, and MAB profiles.
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
}
for _p, _u in _NS_MAP.items():
    ET.register_namespace(_p, _u)


class EapType(Enum):
    """EAP method types used in 802.1X profiles."""
    TLS = 13
    PEAP = 25
    MSCHAPV2 = 26


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
    eap_config: Optional[Union[EapTlsConfig, PeapMsChapV2Config, PeapEapTlsConfig]] = field(default_factory=EapTlsConfig)

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
        SubElement(eap_method_el, "AuthorId", xmlns=NS_EAPCOMMON).text = "0"

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









