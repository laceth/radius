from time import sleep

from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile, WindowsCertStore
from tests.radius.functional.base_classes.radius_eap_tls_test_base import RadiusEapTlsTestBase


# T1316960#
class T1316960_Verify_OID_MSCA_1_3_6_1_4_1_311_21_7(RadiusEapTlsTestBase):
    TAGS = {"smoke"}
    """
    Verify the Decode of the encoded OID when
    using MSCA 1.3.6.1.4.1.311.21.7

    Imports certificates to Windows certificate stores,
    configures LAN profile, triggers NIC toggle, and validates
    successful authentication against the RADIUS server.
    """

    def do_test(self):
        """Execute the EAP-TLS authentication test"""
        auth_nic_profile = AuthNicProfile.EAP_TLS
        certificate_password = "aristo"
        expected_status = AuthenticationStatus.SUCCEEDED

        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.TEST_DECODE_A.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


# T13165931#
class T1316931_Verify_Host_can_Authenticate_over_a_switch_using_EAP_TLS_authentication(RadiusEapTlsTestBase):
    TAGS = {"smoke"}
    """
    Verify a Host can Authenticate over
    a switch using EAP-TLS authentication.

    Imports certificates to Windows certificate stores,
    configures LAN profile, triggers NIC toggle, and validates
    successful authentication against the RADIUS server.
    """

    def do_test(self):
        """Execute the EAP-TLS authentication test"""
        auth_nic_profile = AuthNicProfile.EAP_TLS
        certificate_password = "aristo"
        expected_status = AuthenticationStatus.SUCCEEDED

        try:
            # Step 1: Import certificates
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


# T1316958#
class T1316958_Verify_Microsoft_Certificate_Authority_client_certificate_Pre_Admission_Rule(RadiusEapTlsTestBase):
    TAGS = {"smoke"}
    """
    Verifies a Microsoft-Certificate-Authority
      value can be pulled from a client
      certificate and used in a Pre-Admission Rule

    Imports certificates to Windows certificate stores,
    configures LAN profile, triggers NIC toggle, and validates
    successful authentication against the RADIUS server.
    """

    def do_test(self):
        """Execute the EAP-TLS authentication test"""
        auth_nic_profile = AuthNicProfile.EAP_TLS
        certificate_password = "aristo"
        expected_status = AuthenticationStatus.SUCCEEDED

        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.DOT1X_MSCA_B.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


# T1316959#
class T1316959_Verify_Microsoft_Certificate_Authority_and_Pre_Admission_Rule(RadiusEapTlsTestBase):
    TAGS = {"smoke"}
    """
    Verifies a Microsoft-Certificate-Authority value
      can be pulled from a client certificate and
      used in a Pre-Admission Rule.


    Imports certificates to Windows certificate stores,
    configures LAN profile, triggers NIC toggle, and validates
    successful authentication against the RADIUS server.
    """

    def do_test(self):
        """Execute the EAP-TLS authentication test"""
        auth_nic_profile = AuthNicProfile.EAP_TLS
        certificate_password = "aristo"
        expected_status = AuthenticationStatus.SUCCEEDED

        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.DOT1X_MSCA_E.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


# T1316951#
class T1316951_Verify_Host_Authenticate_over_switch_using_EAP_TLS_authentication(RadiusEapTlsTestBase):
    TAGS = {"smoke"}
    """
   Verify a Host can Authenticate over a
   switch using EAP-TLS authentication

    Imports certificates to Windows certificate stores,
    configures LAN profile, triggers NIC toggle, and validates
    successful authentication against the RADIUS server.
    """

    def do_test(self):
        """Execute the EAP-TLS authentication test"""
        auth_nic_profile = AuthNicProfile.EAP_TLS
        certificate_password = "aristo"
        expected_status = AuthenticationStatus.SUCCEEDED

        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.TEST_DECODE_B.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


# T1316987#
class T1316987_Verify_changing_Radius_certificates(RadiusEapTlsTestBase):
    TAGS = {"smoke", "regression"}
    """
    Verify changing Radius certificates

    Imports certificates to Windows certificate stores,
    configures LAN profile, triggers NIC toggle, and validates
    successful authentication against the RADIUS server.
    """

    def do_test(self):
        """Execute the EAP-TLS authentication test"""
        auth_nic_profile = AuthNicProfile.EAP_TLS
        certificate_password = "aristo"
        expected_status = AuthenticationStatus.SUCCEEDED

        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.TEST_DECODE_B.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


class T1316954_Verifies_Extended_Key_Usage_client_certificate_Pre_Admission_Rule(RadiusEapTlsTestBase):
    TAGS = {"smoke", "regression"}
    """
    Verifies a Extended Key Usage value can be pulled from a
    client certificate and used in a Pre-Admission Rule.

    Imports certificates to Windows certificate stores,
    configures LAN profile, triggers NIC toggle, and validates
    successful authentication against the RADIUS server.
    """

    def do_test(self):
        """Execute the EAP-TLS authentication test"""
        auth_nic_profile = AuthNicProfile.EAP_TLS
        certificate_password = "aristo"
        expected_status = AuthenticationStatus.SUCCEEDED

        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.Dot1x_CLT_B.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise

        sleep(5)

        # DOT1X_CLT_C#
        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.DOT1X_CLT_C.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise

        sleep(5)

        # DOT1X_CLT_D#
        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.DOT1X_CLT_D.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise


class T1316957_Verifies_Extended_Key_Usage_pulled_from_a_client_certificate__Pre_Admission_Rule(RadiusEapTlsTestBase):
    TAGS = {"smoke", "regression"}
    """
    Verifies a Extended Key Usage value can be pulled from
    a client certificate and used in a Pre-Admission Rule.

    Imports certificates to Windows certificate stores,
    configures LAN profile, triggers NIC toggle, and validates
    successful authentication against the RADIUS server.
    """

    def do_test(self):
        """Execute the EAP-TLS authentication test"""
        auth_nic_profile = AuthNicProfile.EAP_TLS
        certificate_password = "aristo"
        expected_status = AuthenticationStatus.SUCCEEDED

        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.DOT1X_CLT_E.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise

        sleep(5)
        # DOT1X_CLT_F#
        #
        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.DOT1X_CLT_F.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise
        sleep(5)

        # DOT1X_CLT_G#
        try:
            # Step 1: Import certificates
            self.cert_config.certificate_filename = WindowsCertStore.DOT1X_CLT_G.value
            self.import_certificates(certificate_password=certificate_password)

            # Step 2: Configure LAN profile
            self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

            # Step 3: Toggle NIC to trigger authentication
            self.toggle_nic()

            # Step 4: Assert authentication status matches expected
            self.assert_authentication_status(expected_status=expected_status)
        except Exception as e:
            log.error(f"Test failed: {e}")
            raise
