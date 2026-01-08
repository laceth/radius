from framework.log.logger import log
from lib.passthrough.enums import AuthenticationStatus, AuthNicProfile, PreAdmissionRuleSet, WindowsCert
from tests.radius.functional.base_classes.radius_eap_tls_test_base import RadiusEapTlsTestBase
 


class T1316958_(RadiusEapTlsTestBase):
    """
    T1316958
    Verifies a Microsoft-Certificate-Authority value can be pulled from a client certificate
    and used in a Pre-Admission Rule.

    TestRail flow (cond slot is your “Rule One”):
      Step 1: Disable NIC; create Rule One with MSCA values (.2,.4,.6,.8,.14,.16,.22,.32); Apply
      Step 2: Enable NIC; verify success
      Step 3: Disable NIC; update Rule One by deselecting .2 only; Apply; enable NIC; verify success
      Step 4: Disable NIC; update Rule One by unselecting all but .14 and .22; Apply; enable NIC; verify success
      Step 5: Disable NIC; update Rule One by unselecting all but .14 and .32; Apply; delete cert B import cert C; enable NIC; verify success
      Step 6: Disable NIC; select all options; Apply; delete cert C import cert D; enable NIC; verify NOT matching rule (expected failure)
    """

    TAGS = {"smoke", "regression"}

    RULE_SLOT = 1  # "Rule One" => config.defpol_cond1.value

    def _expect_auth(self, should_succeed: bool, expected: AuthenticationStatus = AuthenticationStatus.SUCCEEDED):
        """
        should_succeed=True  -> assert authentication reaches SUCCEEDED
        should_succeed=False -> assert authentication does NOT reach SUCCEEDED
        """
        if should_succeed:
            self.assert_authentication_status(expected_status=expected)
            return

        # Negative case: reaching SUCCEEDED is a failure for this step
        try:
            self.assert_authentication_status(expected_status=expected)
        except Exception:
            log.info("Negative case OK: authentication did not reach SUCCEEDED as expected.")
            return
        raise AssertionError("Expected authentication to FAIL, but it SUCCEEDED.")

    def _apply_rule_one(self, rule_set: PreAdmissionRuleSet):
        """
        Mimics UI: disable NIC -> apply rule -> apply/save -> (plugin restart handled in set_pre_admission_rules)
        """
        self.disable_nic()
        log.info(f"Applying Rule One (cond{self.RULE_SLOT}) => {rule_set.name}")
        self.dot1x.set_pre_admission_rules(rule_set.value, condition_slot=self.RULE_SLOT)
        self.enable_nic()

    
    # def _switch_client_cert(self, cert_filename: str, cert_pw: str = "aristo"):
    #     """
    #     Mimics UI: switch client certificate on the Windows host.

    #     """
    
    #     # Best-effort: delete the previously copied PFX file from the remote host
    #     # (this is only the file in C:\\Certificates, NOT the cert in the Windows store)
    #     try:
    #         prev_filename = getattr(self.cert_config, "certificate_filename", None)
    #         if prev_filename and prev_filename != cert_filename:
    #             prev_remote_path = f"{self.cert_config.certificates_path}\\{prev_filename}"
    #             log.info(f"[CertSwitch] Removing previous remote PFX file (best-effort): {prev_remote_path}")
    #             self.passthrough.remove_file(prev_remote_path)
    #     except Exception as e:
    #         log.warning(f"[CertSwitch] Could not remove previous remote PFX file (continuing): {e}")

    #     # Switch config + import (this performs the real Windows store cleanup + import)
    #     self.cert_config.certificate_filename = cert_filename
    #     log.info(f"[CertSwitch] Importing client cert: {cert_filename}")
    #     self.import_certificates(certificate_password=cert_pw)
    def _switch_client_cert(self, cert_filename: str, cert_pw: str = "aristo"):
        """
        Mimics UI: switch client certificate on the Windows host.

        NOTE:
        - We do NOT delete PFX files on disk.
        - We rely on import_certificates() which:
        - extracts thumbprints from the new PFX locally
        - deletes any prior imported certs by thumbprint on the Windows host
        - imports the new PFX into LocalMachine\\My
        - imports the trusted CA cert into LocalMachine\\Root
        """
        self.cert_config.certificate_filename = cert_filename
        log.info(f"[CertSwitch] Importing client cert: {cert_filename}")
        self.import_certificates(certificate_password=cert_pw)

    
    def _authenticate_and_verify(self, should_succeed: bool):
        # Trigger auth
        self.toggle_nic()
        # Verify expected outcome
        self._expect_auth(should_succeed=should_succeed)

    def do_test(self):
        auth_nic_profile = AuthNicProfile.EAP_TLS

        # Configure LAN profile once (safe to do early)
        self.configure_lan_profile(auth_nic_profile=auth_nic_profile)

        # -------------------------
        # Step 0: Start with Cert B (precondition in TestRail)
        # -------------------------
        log.info("Precondition: install client cert B (Dot1xMSCA-CLT-B)")
        self._switch_client_cert(WindowsCert.DOT1X_MSCA_B.value)

        # -------------------------
        # Step 1 + 2: Rule One ALL options; enable; verify success
        # -------------------------
        log.info("Step 1/2: Rule One = ALL (.2,.4,.6,.8,.14,.16,.22,.32), expect SUCCESS with cert B")
        self._apply_rule_one(PreAdmissionRuleSet.T1316958_RULE1_ALL)
        self._authenticate_and_verify(should_succeed=True)

        # -------------------------
        # Step 3: deselect .2 only; verify success (cert B)
        # -------------------------
        log.info("Step 3: Rule One = NO .2, expect SUCCESS with cert B")
        self._apply_rule_one(PreAdmissionRuleSet.T1316958_RULE1_NO_2)
        self._authenticate_and_verify(should_succeed=True)

        # -------------------------
        # Step 4: only .14 and .22; verify success (cert B)
        # -------------------------
        log.info("Step 4: Rule One = ONLY (.14,.22), expect SUCCESS with cert B")
        self._apply_rule_one(PreAdmissionRuleSet.T1316958_RULE1_ONLY_14_22)
        self._authenticate_and_verify(should_succeed=True)

        # -------------------------
        # Step 5: only .14 and .32; swap B -> C; verify success
        # -------------------------
        log.info("Step 5: Rule One = ONLY (.14,.32), swap cert B->C, expect SUCCESS with cert C")
        self._apply_rule_one(PreAdmissionRuleSet.T1316958_RULE1_ONLY_14_32)

        # UI: delete B, import C (contains .2 and .32 per TestRail text)
        self.disable_nic()
        self._switch_client_cert(WindowsCert. DOT1X_MSCA_C.value)
        self.enable_nic()
        self._authenticate_and_verify(should_succeed=True)

        # -------------------------
        # Step 6: select ALL options; swap C -> D; verify failure (no MSCA values)
        # -------------------------
        log.info("Step 6: Rule One = ALL options, swap cert C->D, expect FAIL (cert D does not match)")
        self._apply_rule_one(PreAdmissionRuleSet.T1316958_RULE1_ALL)

        # UI: delete C, import D (contains no MSCA values)
        self.disable_nic()
        self._switch_client_cert(WindowsCert.DOT1X_MSCA_D .value)
        self.enable_nic()
        self._authenticate_and_verify(should_succeed=False)

        log.info("T1316958 completed.")
