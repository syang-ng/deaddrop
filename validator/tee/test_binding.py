"""Regression tests for the evidence boundary with no native dependencies."""

import copy
import unittest
from unittest.mock import patch

from mock_quote import mock_quote
from protocol import experiment, manifest, pack_ciphertext, report_data
from verify import verify_bundle


class EvidenceBindingTest(unittest.TestCase):
    nonce = "21" * 32
    recipient = "age1" + "q" * 58
    ciphertext = b"age-encryption.org/v1\nsynthetic test ciphertext"

    def bundle(self, mode="mock"):
        config, config_hash = experiment()
        statement = manifest(mode, self.nonce, self.recipient, config, config_hash,
                             "pass", self.ciphertext)
        return {"manifest": statement, "ciphertext_b64": pack_ciphertext(self.ciphertext),
                "quote_hex": mock_quote(report_data(statement)).hex(), "metrics": {}}

    def test_checks_mock_in_explicit_mock_mode(self):
        result = verify_bundle(self.bundle(), self.nonce, self.recipient, "mock")
        self.assertEqual(result["verification"], "unsigned_mock_checked")

    def test_default_hardware_path_cannot_accept_mock_evidence(self):
        with self.assertRaisesRegex(ValueError, "expected tdx evidence"):
            verify_bundle(self.bundle(), self.nonce, self.recipient, "tdx")

    @patch("verify.verify_tdx", side_effect=ValueError("DCAP rejected mock bytes"))
    def test_relabelled_mock_evidence_requires_dcap(self, verify_tdx):
        bundle = self.bundle(mode="tdx")
        with self.assertRaisesRegex(ValueError, "DCAP rejected"):
            verify_bundle(bundle, self.nonce, self.recipient, "tdx")
        verify_tdx.assert_called_once()

    def test_nonce_and_recipient_are_checked_against_caller_inputs(self):
        for nonce, recipient in (("23" * 32, self.recipient), (self.nonce, "age1" + "p" * 58)):
            with self.subTest(nonce=nonce, recipient=recipient):
                with self.assertRaisesRegex(ValueError, "binding inputs"):
                    verify_bundle(self.bundle(), nonce, recipient, "mock")

    def test_ciphertext_verdict_and_state_substitution_are_rejected(self):
        original = self.bundle()
        tampered = copy.deepcopy(original)
        tampered["ciphertext_b64"] = pack_ciphertext(self.ciphertext + b" altered")
        tampered_verdict = copy.deepcopy(original)
        tampered_verdict["manifest"]["verdict"] = "fail"
        tampered_state = copy.deepcopy(original)
        tampered_state["manifest"]["blockchain"]["block_number"] = 2
        for sample in (tampered, tampered_verdict, tampered_state):
            with self.assertRaises(ValueError):
                verify_bundle(sample, self.nonce, self.recipient, "mock")


if __name__ == "__main__":
    unittest.main()
