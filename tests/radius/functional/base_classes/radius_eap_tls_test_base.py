from lib.passthrough.enums import AuthNicProfile
from tests.radius.functional.base_classes.radius_certificates_test_base import RadiusCertificatesTestBase


class RadiusEapTlsTestBase(RadiusCertificatesTestBase):
    """Base class for EAP-TLS authentication tests."""

    def import_eap_tls_certificates(self, certificate_password: str = 'aristo'):
        """Import EAP-TLS certificates. Alias for import_certificates()."""
        self.import_certificates(certificate_password)

    def remove_eap_tls_certificates(self):
        """Remove EAP-TLS certificates. Alias for remove_certificates()."""
        self.remove_certificates()

