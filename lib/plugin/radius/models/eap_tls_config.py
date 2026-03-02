"""
Configuration dataclasses for RADIUS certificate-based authentication (EAP-TLS, PEAP-EAP-TLS).
"""
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CertificateAuthConfig:
    """
    Configuration for certificate-based authentication setup on Windows endpoint.

    Supports both EAP-TLS and PEAP-EAP-TLS which use the same certificate import mechanism.

    Usage:
        config = CertificateAuthConfig()
    """
    # Remote Windows paths
    certificates_path: str = r'C:\Certificates'
    profiles_path: str = r'C:\Profiles'

    # Certificate configuration
    certificate_filename: str = 'Dot1x-CLT-G.pfx'
    certificate_password: str = 'aristo'

    # NIC configuration
    nicname: str = 'pciPassthru0'

    @property
    def local_certificate_path(self) -> str:
        return _find_resource(self.certificate_filename)

    def validate(self):
        """Validate that required files exist."""
        if not Path(self.local_certificate_path).exists():
            raise FileNotFoundError(f"Certificate not found: {self.local_certificate_path}")



# =============================================================================
# Private: Resource path utilities
# =============================================================================

_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_RESOURCES_DIR = _PROJECT_ROOT / 'resources'
_CERTIFICATES_DIR = _RESOURCES_DIR / 'radius' / 'certificates'


def _find_resource(filename: str) -> str:
    # First check direct paths
    for directory in [_CERTIFICATES_DIR, _RESOURCES_DIR]:
        path = directory / filename
        if path.exists():
            return str(path)

    # Search subdirectories recursively
    for directory in [_CERTIFICATES_DIR, _RESOURCES_DIR]:
        for path in directory.rglob(filename):
            if path.exists():
                return str(path)

    return str(_CERTIFICATES_DIR / filename)

