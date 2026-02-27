"""
Base class for certificate-based RADIUS authentication tests (EAP-TLS, PEAP-EAP-TLS).

This module provides the RadiusCertificatesTestBase class that handles
certificate import operations shared by both EAP-TLS and PEAP-EAP-TLS tests.
"""
from typing import Union, cast
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
from cryptography.hazmat.primitives import hashes
import tempfile
import os

from framework.log.logger import log
from lib.passthrough.enums import WindowsCert
from lib.passthrough.lan_profile_builder import LanProfile
from lib.external_servers.ocsp_server import OcspServer
from lib.plugin.radius.enums import RadiusAuthStatus
from lib.plugin.radius.models.eap_tls_config import CertificateAuthConfig
from tests.radius.radius_test_base import RadiusTestBase


class RadiusCertificatesTestBase(RadiusTestBase):
    """
    Base class for certificate-based authentication tests (EAP-TLS, PEAP-EAP-TLS).

    Both authentication methods use the same PFX certificate and import mechanism:
    - Personal certificate (with private key) -> LocalMachine\\My store
    - Trusted CA certificate -> LocalMachine\\Root store

    Subclasses should override DEFAULT_EAP_TYPE to set the authentication type.
    """

    # Certificate store names
    PERSONAL_CERT_STORE = 'My'
    TRUSTED_CERT_STORE = 'Root'
    STORE_LOCATION = 'LocalMachine'

    # EAP type label used in logs and host-property verification — override in subclasses
    DEFAULT_EAP_TYPE = "EAP-TLS"

    def __init__(self, ca, em, radius, switch, passthrough, version="1.0.0", ocsp=None):
        super().__init__(ca, em, radius, switch, passthrough, version=version)
        self.cert_config = CertificateAuthConfig()
        self.nicname = self.cert_config.nicname
        self.trusted_cert_thumbprint = None
        self.personal_cert_thumbprint = None
        self._trusted_cert_der = None
        if ocsp:
            self.ocsp = cast(OcspServer, ocsp)

    def do_setup(self):
        """Setup phase: prepare test environment."""
        log.info(f"=== Starting {self.DEFAULT_EAP_TYPE} Test Setup ===")

        # Run common setup (cleanup endpoint, configure switch)
        super().do_setup()

        # Clean up all test certificates from Windows stores
        self.cleanup_all_test_certificates()

        log.info(f"NIC: {self.nicname}")

    def do_teardown(self):
        """Cleanup phase: remove imported certificates."""
        log.info(f"=== {self.DEFAULT_EAP_TYPE} Test Teardown ===")
        try:
            self.remove_certificates()
        except Exception as e:
            log.warning(f"Failed to remove certificates during teardown: {e}")
        super().do_teardown()

    # =========================================================================
    # Authentication Verification
    # =========================================================================

    def verify_authentication_on_ca(
            self,
            switch_ip: str = None,
            ca_ip: str = None,
            auth_status: Union[RadiusAuthStatus, str] = RadiusAuthStatus.ACCESS_ACCEPT,
            login_type: str = "dot1x_computer_login",
            certificate_name: str = None
    ):
        """
        Verify certificate-based authentication properties on CounterAct.
        Extends base class verify_authentication_on_ca with certificate-specific fields.

        Args:
            switch_ip: Expected Switch IP (dot1x_NAS_addr). Defaults to self.switch.ip
            ca_ip: Expected CounterACT IP (dot1x_auth_appliance). Defaults to self.ca.ipaddress
            auth_status: Expected auth status (dot1x_host_auth_status). Default: RadiusAuthStatus.ACCESS_ACCEPT
            login_type: Expected login type (dot1x_login_type). Default: "dot1x_computer_login"
            certificate_name: Expected certificate name (dot1x_host). Defaults to certificate filename without .pfx
        """
        # Get host ID once using base class helper
        if not self.host_id:
            self.host_id = self._get_host_id()
        log.info(f"Verifying {self.DEFAULT_EAP_TYPE} authentication for host: {self.host_id}")

        # Convert enum to string value if needed
        auth_status_value = auth_status.value if isinstance(auth_status, RadiusAuthStatus) else auth_status

        # Verify common fields using base class helper
        self._verify_common_properties(
            host_id=self.host_id,
            switch_ip=switch_ip,
            ca_ip=ca_ip,
            auth_state=auth_status_value
        )

        # Determine EAP type based on auth profile
        eap_type = self.DEFAULT_EAP_TYPE

        # Get certificate name (without .pfx extension)
        cert_name = certificate_name or self.cert_config.certificate_filename.replace('.pfx', '')

        # Build certificate-based authentication properties check list
        cert_properties_check_list = [
            {"property_field": "dot1x_host_auth_status", "expected_value": auth_status_value},
            {"property_field": "dot1x_login_type", "expected_value": login_type},
            {"property_field": "dot1x_fr_eap_type", "expected_value": eap_type},
            {"property_field": "dot1x_host", "expected_value": cert_name},
        ]

        self.ca.check_properties(self.host_id, cert_properties_check_list)
        log.info(f"{self.DEFAULT_EAP_TYPE} authentication verification completed successfully")


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
        cmd = self._ps_delete_cert(store_name, thumbprint)
        result = self.passthrough.execute_command(cmd)
        log.info(f"[OK] {result.strip()}")

    def _import_pfx_to_personal_store(self, pfx_path: str, password: str):
        """Import PFX certificate to Personal (My) store on LocalMachine."""
        log.info("Importing PFX to Personal store...")
        cmd = self._ps_import_pfx(pfx_path, password)
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
            cmd = self._ps_import_cer(remote_cer_path, self.TRUSTED_CERT_STORE)
            result = self.passthrough.execute_command(cmd)
            log.info(f"[OK] {result.strip()}")

            self.passthrough.remove_file(remote_cer_path)
        finally:
            os.unlink(local_cer_path)

    # =========================================================================
    # PowerShell Command Builders
    # =========================================================================

    def _ps_delete_cert(self, store_name: str, thumbprint: str) -> str:
        """Build PowerShell command to delete certificate by thumbprint."""
        return f'''
$cert = Get-ChildItem -Path Cert:\\{self.STORE_LOCATION}\\{store_name} |
    Where-Object {{ $_.Thumbprint -eq "{thumbprint}" }}
if ($cert) {{
    Remove-Item -Path $cert.PSPath -Force
    "Deleted certificate from {store_name}"
}} else {{
    "Certificate not found in {store_name}"
}}'''

    def _ps_import_pfx(self, pfx_path: str, password: str) -> str:
        """Build PowerShell command to import PFX certificate."""
        return f'''
$securePassword = ConvertTo-SecureString -String "{password}" -Force -AsPlainText
Import-PfxCertificate `
    -FilePath "{pfx_path}" `
    -CertStoreLocation Cert:\\{self.STORE_LOCATION}\\{self.PERSONAL_CERT_STORE} `
    -Password $securePassword `
    -Exportable | Out-Null
"PFX imported successfully"'''

    def _ps_import_cer(self, cer_path: str, store_name: str) -> str:
        """Build PowerShell command to import .cer certificate."""
        return f'''
Import-Certificate `
    -FilePath "{cer_path}" `
    -CertStoreLocation Cert:\\{self.STORE_LOCATION}\\{store_name} | Out-Null
"Certificate imported to {store_name}"'''

    def remove_certificates(self):
        """Remove certificates from Windows certificate stores."""
        log.info("Removing certificates...")

        if self.personal_cert_thumbprint:
            self._delete_cert_by_thumbprint(self.PERSONAL_CERT_STORE, self.personal_cert_thumbprint)

        if self.trusted_cert_thumbprint:
            self._delete_cert_by_thumbprint(self.TRUSTED_CERT_STORE, self.trusted_cert_thumbprint)

        log.info("Certificates removed")

    def move_ca_cert_to_personal_store(self):
        """
        Move the CA certificate from Trusted Root Certification Authorities to Personal store.

        This simulates the MMC operation of moving the CA cert to the wrong store,
        which should cause certificate-based authentication to fail.
        """
        if not self.trusted_cert_thumbprint:
            raise RuntimeError("Trusted certificate thumbprint not available. Import certificates first.")

        log.info("Moving CA certificate from Root to Personal store...")

        cmd = f'''
$thumbprint = "{self.trusted_cert_thumbprint}"
$cert = Get-ChildItem -Path Cert:\\{self.STORE_LOCATION}\\{self.TRUSTED_CERT_STORE} | Where-Object {{ $_.Thumbprint -eq $thumbprint }}
if ($cert) {{
    # Export the certificate
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    
    # Import to Personal store
    $personalStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("{self.PERSONAL_CERT_STORE}", "{self.STORE_LOCATION}")
    $personalStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $personalStore.Add($cert)
    $personalStore.Close()
    
    # Remove from Root store
    Remove-Item -Path $cert.PSPath -Force
    "Moved CA certificate from Root to Personal store"
}} else {{
    "CA certificate not found in Root store"
}}'''
        result = self.passthrough.execute_command(cmd)
        log.info(f"[OK] {result.strip()}")

    # Known CA certificate names that may be imported with client certs
    KNOWN_CA_CERTS = ["Dot1x-CA", "Dot1xMSCA-CA"]

    def cleanup_all_test_certificates(self):
        """
        Remove all test certificates from Windows Personal and Trusted Root stores.

        Uses a single PowerShell command to delete all certificates matching any of the
        known test certificate names from both stores. This is much faster than
        individual delete operations.
        """
        log.info("Cleaning up all test certificates from Windows stores...")

        # Build list of all certificate name patterns to delete
        cert_patterns = []

        # Add client certificate names from WindowsCert enum
        for cert_enum in WindowsCert:
            cert_name = cert_enum.value.replace('.pfx', '')
            cert_patterns.append(cert_name)

        # Add known CA certificate names
        cert_patterns.extend(self.KNOWN_CA_CERTS)

        # Build PowerShell pattern for matching any of the cert names
        # Using -or conditions for each pattern
        conditions = ' -or '.join([f'$_.Subject -like "*{name}*"' for name in cert_patterns])

        cmd = f'''
$deleted = @()
foreach ($store in @("{self.PERSONAL_CERT_STORE}", "{self.TRUSTED_CERT_STORE}")) {{
    $certs = Get-ChildItem -Path Cert:\\{self.STORE_LOCATION}\\$store | Where-Object {{ {conditions} }}
    foreach ($cert in $certs) {{
        Remove-Item -Path $cert.PSPath -Force
        $deleted += "Deleted: $($cert.Subject) from $store"
    }}
}}
if ($deleted.Count -gt 0) {{ $deleted -join "`n" }} else {{ "No test certificates found" }}
'''
        try:
            result = self.passthrough.execute_command(cmd)
            if result and "Deleted:" in result:
                for line in result.strip().split('\n'):
                    if "Deleted:" in line:
                        log.info(f"[OK] {line.strip()}")
            else:
                log.debug("No test certificates found to clean up")
        except Exception as e:
            log.warning(f"Certificate cleanup failed: {e}")

        log.info("Test certificates cleanup completed")

    def _delete_cert_by_subject(self, store_name: str, subject_contains: str):
        """
        Delete certificate(s) from specified store where subject contains the given string.
        Logs warning if deletion fails.

        Args:
            store_name: Certificate store name (My, Root, etc.)
            subject_contains: String to match in certificate subject (CN)
        """
        cmd = f'''$certs = Get-ChildItem -Path Cert:\\{self.STORE_LOCATION}\\{store_name} | Where-Object {{ $_.Subject -like "*{subject_contains}*" }}; if ($certs) {{ $certs | ForEach-Object {{ Remove-Item -Path $_.PSPath -Force; "Deleted: $($_.Subject) from {store_name}" }} }}'''
        try:
            result = self.passthrough.execute_command(cmd)
            if result and "Deleted:" in result:
                log.info(f"[OK] {result.strip()}")
        except Exception as e:
            log.warning(f"Failed to delete cert '{subject_contains}' from {store_name}: {e}")

    # =========================================================================
    # LAN Profile Management
    # =========================================================================

    def configure_lan_profile(
        self,
        lan_profile: LanProfile = None,
        remote_profiles_path: str = None,
    ):
        """
        Configure LAN profile using a LanProfile builder.

        Args:
            lan_profile: A ``LanProfile`` instance. Required.
            remote_profiles_path: Remote directory. Defaults to cert_config.profiles_path.
        """
        if lan_profile is None:
            raise ValueError("lan_profile must be provided")
        super().configure_lan_profile(
            lan_profile=lan_profile,
            remote_profiles_path=remote_profiles_path or self.cert_config.profiles_path,
        )
