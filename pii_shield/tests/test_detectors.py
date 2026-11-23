import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import detectors as d  # noqa: E402


def labels(text, **kw):
    return [f.detector for f in d.scan(text, **kw)]


class ChecksumTests(unittest.TestCase):
    def test_verhoeff(self):
        self.assertTrue(d.verhoeff_valid("234567890124"))
        self.assertFalse(d.verhoeff_valid("234567890125"))

    def test_luhn(self):
        self.assertTrue(d.luhn_valid("4111111111111111"))
        self.assertFalse(d.luhn_valid("4111111111111112"))


class DetectionTests(unittest.TestCase):
    def test_sample_finds_everything(self):
        found = set(labels(d.SAMPLE_TEXT))
        self.assertEqual(found, {"email", "phone", "dob", "pan", "aadhaar", "upi", "card", "ifsc", "ip"})

    def test_aadhaar_confidence(self):
        good = d.scan("id 2345 6789 0124")[0]
        bad = d.scan("id 2345 6789 0125")[0]
        self.assertEqual((good.detector, good.confidence), ("aadhaar", "high"))
        self.assertEqual((bad.detector, bad.confidence), ("aadhaar", "low"))

    def test_aadhaar_cannot_start_with_0_or_1(self):
        self.assertEqual(labels("1234 5678 9012"), [])

    def test_card_beats_aadhaar_and_phone(self):
        self.assertEqual(labels("card 4111 1111 1111 1111"), ["card"])

    def test_invalid_card_is_not_reported_as_aadhaar(self):
        self.assertEqual(labels("4111 1111 1111 1112"), [])

    def test_upi_is_not_email(self):
        self.assertEqual(labels("pay alex@okhdfcbank now"), ["upi"])
        self.assertEqual(labels("write to alex@upi.example.org"), ["email"])

    def test_phone_formats(self):
        for value in ("9876543210", "+91 98765 43210", "+919876543210", "98765-43210"):
            self.assertEqual(labels(f"call {value}."), ["phone"], value)
        self.assertEqual(labels("call 5876543210"), [])

    def test_pan_holder_type(self):
        self.assertEqual(d.scan("ABCPE1234F")[0].confidence, "high")
        self.assertEqual(d.scan("ABCDE1234F")[0].confidence, "low")

    def test_dates_must_be_real(self):
        self.assertEqual(labels("born 12/08/1994."), ["dob"])
        self.assertEqual(labels("on 31/02/1994"), [])
        self.assertEqual(labels("on 12/08/2999"), [])

    def test_ip_range(self):
        self.assertEqual(labels("from 10.0.0.255"), ["ip"])
        self.assertEqual(labels("from 10.0.0.256"), [])

    def test_gstin_does_not_double_report_pan(self):
        self.assertEqual(labels("GST 27ABCPE1234F1Z5"), ["gstin"])

    def test_enabled_filter(self):
        self.assertEqual(labels(d.SAMPLE_TEXT, enabled=["email"]), ["email"])
        self.assertEqual(labels(d.SAMPLE_TEXT, enabled=[]), [])

    def test_positions(self):
        f = d.scan("a\nb x@y.io")[0]
        self.assertEqual((f.line, f.column), (2, 3))


class RedactionTests(unittest.TestCase):
    text = "Mail meera@example.com or call 98765 43210."

    def test_styles(self):
        f = d.scan(self.text)
        self.assertEqual(d.redact(self.text, f, "label"), "Mail [EMAIL] or call [PHONE].")
        self.assertEqual(d.redact(self.text, f, "mask"), "Mail m***@example.com or call ******3210.")
        block = d.redact(self.text, f, "block")
        self.assertNotIn("meera", block)
        self.assertEqual(len(block), len(self.text))

    def test_no_original_values_leak_in_redacted_output(self):
        f = d.scan(d.SAMPLE_TEXT)
        for style in d.STYLES:
            out = d.redact(d.SAMPLE_TEXT, f, style)
            for secret in ("meera.nair@example.com", "ABCPE1234F", "2345 6789 0124", "4111 1111 1111 1111"):
                self.assertNotIn(secret, out, style)

    def test_segments_roundtrip(self):
        f = d.scan(d.SAMPLE_TEXT)
        self.assertEqual("".join(p["text"] for p in d.segments(d.SAMPLE_TEXT, f)), d.SAMPLE_TEXT)
        self.assertEqual("".join(p["text"] for p in d.segments(d.SAMPLE_TEXT, f, "label")),
                         d.redact(d.SAMPLE_TEXT, f, "label"))

    def test_summary(self):
        s = d.summarize(d.scan(d.SAMPLE_TEXT))
        self.assertEqual(s["risk"], "high")
        self.assertEqual(s["total"], sum(s["by_severity"].values()))
        self.assertEqual(d.summarize([])["risk"], "none")


if __name__ == "__main__":
    unittest.main()
