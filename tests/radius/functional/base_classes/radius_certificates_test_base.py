"""
Base class for certificate-based RADIUS authentication tests (EAP-TLS, PEAP-EAP-TLS).

This module provides the RadiusCertificatesTestBase class that handles
certificate import operations shared by both EAP-TLS and PEAP-EAP-TLS tests.
"""
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
from cryptography.hazmat.primitives import hashes
import tempfile
import os

from framework.log.logger import log
from lib.passthrough.enums import AuthNicProfile
from lib.plugin.radius.models.eap_tls_config import CertificateAuthConfig
from tests.radius.radius_test_base import RadiusTestBase


class RadiusCertificatesTestBase(RadiusTestBase):
    """
    Base class for certificate-based authentication tests (EAP-TLS, PEAP-EAP-TLS).

    Both authentication methods use the same PFX certificate and import mechanism:
    - Personal certificate (with private key) -> LocalMachine\\My store
    - Trusted CA certificate -> LocalMachine\\Root store

    Subclasses should override DEFAULT_AUTH_PROFILE to set the authentication type.
    """

    # Certificate store names
    PERSONAL_CERT_STORE = 'My'
    TRUSTED_CERT_STORE = 'Root'
    STORE_LOCATION = 'LocalMachine'

    # Default auth profile - override in subclasses
    DEFAULT_AUTH_PROFILE = AuthNicProfile.EAP_TLS

    def __init__(self, ca, em, radius, switch, passthrough, version="1.0.0"):
        super().__init__(ca, em, radius, switch, passthrough, version)
        self.cert_config = CertificateAuthConfig(auth_nic_profile=self.DEFAULT_AUTH_PROFILE)
        self.nicname = self.cert_config.nicname
        self.trusted_cert_thumbprint = None
        self.personal_cert_thumbprint = None
        self._trusted_cert_der = None

    def do_setup(self):
        """Setup phase: prepare test environment."""
        log.info(f"=== Starting {self.DEFAULT_AUTH_PROFILE.name} Test Setup ===")
        log.info(f"NIC: {self.nicname}")

    def do_teardown(self):
        """Cleanup phase: remove imported certificates."""
        log.info(f"=== {self.DEFAULT_AUTH_PROFILE.name} Test Teardown ===")
        try:
            self.remove_certificates()
        except Exception as e:
            log.warning(f"Failed to remove certificates during teardown: {e}")
        super().do_teardown()

    # =========================================================================
    # Certificate Import
    # =========================================================================

    def import_certificates(self, certificate_password: str = 'aristo'):
        """
        Import certificates on Windows endpoint for certificate-based authentication.

        Works for both EAP-TLS and PEAP-EAP-TLS as they use the same certificate format.

        Workflow:
        1. Read PFX locally and extract thumbprints and trusted cert using Python
        2. Copy PFX certificate to target machine
        3. Delete old certificates from stores
        4. Import PFX to Personal (My) store on LocalMachine
        5. Copy trusted cert (.cer) to target and import to Root store

        Args:
            certificate_password: Password for the PFX certificate
        """
        self.cert_config.certificate_password = certificate_password
        self.cert_config.validate()

        config = self.cert_config
        log.info(f"Importing certificate: {config.certificate_filename}")

        # Step 1: Read PFX locally and extract thumbprints + trusted cert DER
        self._get_pfx_thumbprints_local(config.local_certificate_path, certificate_password)

        # Step 2: Copy PFX certificate to remote machine
        remote_cert_path = f"{config.certificates_path}\\{config.certificate_filename}"
        self.passthrough.create_directory(config.certificates_path)
        self.passthrough.copy_file_to_remote(config.local_certificate_path, remote_cert_path)
        log.info(f"[OK] PFX copied to {remote_cert_path}")

        # Step 3: Delete old certificates from stores
        self._delete_old_certificates()

        # Step 4: Import PFX to Personal store on LocalMachine
        self._import_pfx_to_personal_store(remote_cert_path, certificate_password)

        # Step 5: Copy trusted cert and import to Root store
        self._import_trusted_cert_to_root_store(config.certificates_path)

        log.info("Certificate import completed")

    def _get_pfx_thumbprints_local(self, pfx_path: str, password: str):
        """Read PFX file locally and extract thumbprints and trusted cert DER bytes."""
        log.info(f"Reading PFX file locally: {pfx_path}")

        with open(pfx_path, 'rb') as f:
            pfx_data = f.read()

        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            pfx_data,
            password.encode('utf-8')
        )

        if certificate:
            self.personal_cert_thumbprint = certificate.fingerprint(hashes.SHA1()).hex().upper()
            log.info(f"[OK] Personal cert thumbprint: {self.personal_cert_thumbprint}")
            log.info(f"     Subject: {certificate.subject}")
        else:
            raise RuntimeError("No personal certificate found in PFX")

        if additional_certs and len(additional_certs) > 0:
            trusted_cert = additional_certs[0]
            self.trusted_cert_thumbprint = trusted_cert.fingerprint(hashes.SHA1()).hex().upper()
            self._trusted_cert_der = trusted_cert.public_bytes(Encoding.DER)
            log.info(f"[OK] Trusted cert thumbprint: {self.trusted_cert_thumbprint}")
            log.info(f"     Subject: {trusted_cert.subject}")
        else:
            raise RuntimeError("No CA/trusted certificate found in PFX")

    def _delete_old_certificates(self):
        """Delete old certificates from Personal and Trusted stores."""
        log.info("Deleting old certificates...")

        if self.personal_cert_thumbprint:
            self._delete_cert_by_thumbprint(self.PERSONAL_CERT_STORE, self.personal_cert_thumbprint)

        if self.trusted_cert_thumbprint:
            self._delete_cert_by_thumbprint(self.PERSONAL_CERT_STORE, self.trusted_cert_thumbprint)
            self._delete_cert_by_thumbprint(self.TRUSTED_CERT_STORE, self.trusted_cert_thumbprint)

    def _delete_cert_by_thumbprint(self, store_name: str, thumbprint: str):
        """Delete certificate by thumbprint from specified store."""
        cmd = f'''
$cert = Get-ChildItem -Path Cert:\\{self.STORE_LOCATION}\\{store_name} | Where-Object {{ $_.Thumbprint -eq "{thumbprint}" }}
if ($cert) {{
    Remove-Item -Path $cert.PSPath -Force
    Write-Output "Deleted certificate {thumbprint} from {store_name}"
}} else {{
    Write-Output "Certificate {thumbprint} not found in {store_name}"
}}
'''
        result = self.passthrough.execute_command(cmd)
        log.info(f"[OK] {result.strip()}")

    def _import_pfx_to_personal_store(self, pfx_path: str, password: str):
        """Import PFX certificate to Personal (My) store on LocalMachine."""
        log.info("Importing PFX to Personal store...")
        cmd = f'''
$password = ConvertTo-SecureString -String "{password}" -Force -AsPlainText
Import-PfxCertificate -FilePath "{pfx_path}" -CertStoreLocation Cert:\\{self.STORE_LOCATION}\\{self.PERSONAL_CERT_STORE} -Password $password -Exportable
Write-Output "PFX imported successfully"
'''
        result = self.passthrough.execute_command(cmd)
        log.info(f"[OK] {result.strip()}")

    def _import_trusted_cert_to_root_store(self, remote_certs_path: str):
        """Export trusted cert locally as .cer and copy to remote, then import to Root store."""
        if not self._trusted_cert_der:
            raise RuntimeError("Trusted certificate DER bytes not available")

        with tempfile.NamedTemporaryFile(suffix='.cer', delete=False) as tmp:
            tmp.write(self._trusted_cert_der)
            local_cer_path = tmp.name

        try:
            remote_cer_path = f"{remote_certs_path}\\trusted_ca.cer"
            log.info(f"Copying trusted cert to {remote_cer_path}")
            self.passthrough.copy_file_to_remote(local_cer_path, remote_cer_path)

            log.info("Importing trusted cert to Root store...")
            cmd = f'''
Import-Certificate -FilePath "{remote_cer_path}" -CertStoreLocation Cert:\\{self.STORE_LOCATION}\\{self.TRUSTED_CERT_STORE}
Write-Output "Trusted cert imported to Root store"
'''
            result = self.passthrough.execute_command(cmd)
            log.info(f"[OK] {result.strip()}")

            self.passthrough.remove_file(remote_cer_path)
        finally:
            os.unlink(local_cer_path)

    def remove_certificates(self):
        """Remove certificates from Windows certificate stores."""
        log.info("Removing certificates...")

        if self.personal_cert_thumbprint:
            self._delete_cert_by_thumbprint(self.PERSONAL_CERT_STORE, self.personal_cert_thumbprint)

        if self.trusted_cert_thumbprint:
            self._delete_cert_by_thumbprint(self.TRUSTED_CERT_STORE, self.trusted_cert_thumbprint)

        log.info("Certificates removed")

    # =========================================================================
    # LAN Profile Management
    # =========================================================================

    def configure_lan_profile(self, auth_nic_profile: AuthNicProfile = None):
        """Configure LAN profile using certificate auth config paths."""
        if auth_nic_profile is None:
            auth_nic_profile = self.DEFAULT_AUTH_PROFILE
        self.cert_config.auth_nic_profile = auth_nic_profile
        super().configure_lan_profile(
            auth_nic_profile=auth_nic_profile,
            local_profile_path=self.cert_config.local_lan_profile_path,
            remote_profiles_path=self.cert_config.profiles_path
        )
