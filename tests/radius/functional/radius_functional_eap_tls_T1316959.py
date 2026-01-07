from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile
from lib.passthrough.enums import WindowsCert, PreAdmissionRuleSet
from tests.radius.functional.base_classes.radius_eap_tls_test_base import RadiusEapTlsTestBase


class T1316959_Verify_Microsoft_Certificate_Authority_and_Pre_Admission_Rule(RadiusEapTlsTestBase):
    """
    DOT | Verify a condition that contains multiple MSCA criterions using EAP-TLS.

    Expected behavior (per TestRail screenshots):
      1) Configure Rule One (Priority 1): MSCA .1 and .14
      2) With cert E -> auth succeeds AND matches Pre-Admission rule 1
      3) Swap cert to G -> auth succeeds but should NOT match Rule One (rule mismatch)
      4) Configure Rule Two (Priority 2): (.5 + .19) AND (.11 + .19)
      5) Swap cert to F -> auth succeeds AND matches Pre-Admission rule 2
"""
    
    TAGS = {"smoke", "regression"}

    def do_test(self):
        auth_nic_profile = AuthNicProfile.EAP_TLS
        cert_pw = "aristo"

        # Configure LAN profile once for EAP-TLS
        self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

        # Step 1: Disable NIC + set Rule One in Priority 1 (cond1)
        self.disable_nic()
        log.info("Setting Pre-Admission Rule ONE at Priority 1 (defpol_cond1)")
        self.dot1x.set_pre_admission_rules(PreAdmissionRuleSet.RULE1.value, condition_slot=1)

        # Step 2: Enable NIC + import cert E + expect auth SUCCESS + Rule 1 match
        self.enable_nic()
        self._import_and_auth(WindowsCert.DOT1X_MSCA_E.value, cert_pw, expect_status=AuthenticationStatus.SUCCEEDED)
        # TODO: CA-side rule match assertion
        # self.verify_authentication_on_ca(expected_rule="Pre-Admission rule 1")

        # Step 3: Disable NIC + swap to cert G + expect auth SUCCESS but NOT match Rule 1
        self.disable_nic()
        self._import_and_auth(WindowsCert.DOT1X_MSCA_G.value, cert_pw, expect_status=AuthenticationStatus.SUCCEEDED)
        self.enable_nic()
        self.toggle_nic()
        # TODO: CA-side rule non-match assertion
        # self.verify_authentication_on_ca(not_expected_rule="Pre-Admission rule 1")

        # Step 4: Disable NIC + set Rule Two at Priority 2 (condition 2)
        self.disable_nic()
        log.info("Setting Pre-Admission Rule TWO at Priority 2 (defpol_cond2)")
        self.dot1x.set_pre_admission_rules(PreAdmissionRuleSet.RULE2.value, condition_slot=2)
        self.enable_nic()

        # Step 5: Swap to cert F + expect auth SUCCESS + Rule 2 match
        self._import_and_auth(WindowsCert.DOT1X_MSCA_F.value, cert_pw, expect_status=AuthenticationStatus.SUCCEEDED)
        # TODO: CA-side rule match assertion
        # self.verify_authentication_on_ca(expected_rule="Pre-Admission rule 2")

        log.info("T1316959 completed successfully.")

    def _import_and_auth(self, cert_filename: str, cert_pw: str, expect_status: AuthenticationStatus):
        log.info(f"Importing client cert: {cert_filename}")
        self.cert_config.certificate_filename = cert_filename
        self.import_certificates(certificate_password=cert_pw)

        self.toggle_nic()
        self.assert_authentication_status(expected_status=expect_status)
