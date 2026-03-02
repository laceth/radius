from tests.radius.functional.base_classes.radius_certificates_test_base import RadiusCertificatesTestBase


class RadiusPeapEapTlsTestBase(RadiusCertificatesTestBase):
    """Base class for PEAP-EAP-TLS authentication tests."""
    DEFAULT_EAP_TYPE = "PEAP-EAP-TLS"

    def import_peap_eap_tls_certificates(self, certificate_password: str = 'aristo'):
        """Import PEAP-EAP-TLS certificates. Alias for import_certificates()."""
        self.import_certificates(certificate_password)

    def remove_peap_eap_tls_certificates(self):
        """Remove PEAP-EAP-TLS certificates. Alias for remove_certificates()."""
        self.remove_certificates()


