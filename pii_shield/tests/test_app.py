import io
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app  # noqa: E402
import detectors as d  # noqa: E402


class AppTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "RATE_LIMIT_PER_MIN": 1000})
        self.client = self.app.test_client()

    def token(self):
        html = self.client.get("/").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def post(self, **data):
        data.setdefault("csrf_token", self.token())
        return self.client.post("/", data=data, content_type="multipart/form-data")

    def test_pages_load(self):
        for path in ("/", "/how-it-works", "/api", "/privacy", "/healthz", "/api/v1/detectors"):
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_404_page(self):
        r = self.client.get("/nope")
        self.assertEqual(r.status_code, 404)
        self.assertIn("Page not found", r.get_data(as_text=True))

    def test_security_headers(self):
        r = self.client.get("/")
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")

    def test_scan_form(self):
        r = self.post(text=d.SAMPLE_TEXT, style="label", detectors=list(d.DETECTOR_IDS))
        html = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Scan results", html)
        self.assertIn("[AADHAAR]", html)
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_csrf_required(self):
        self.client.get("/")
        r = self.client.post("/", data={"text": "x@y.io", "csrf_token": "wrong"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("session expired", r.get_data(as_text=True))

    def test_empty_and_no_types(self):
        self.assertEqual(self.post(text="   ").status_code, 400)
        r = self.post(text="a@b.io")  # no detectors selected
        self.assertEqual(r.status_code, 400)
        self.assertIn("Select at least one", r.get_data(as_text=True))

    def test_html_is_escaped(self):
        r = self.post(text='<script>alert(1)</script> a@b.io', detectors="email")
        html = r.get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_upload(self):
        r = self.post(text="", detectors="email", file=(io.BytesIO(b"mail me: a@b.io"), "n.txt"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("uploaded file", r.get_data(as_text=True))
        bad = self.post(text="", detectors="email", file=(io.BytesIO(b"x"), "n.exe"))
        self.assertEqual(bad.status_code, 400)
        binary = self.post(text="", detectors="email", file=(io.BytesIO(b"\x00\x01"), "n.txt"))
        self.assertEqual(binary.status_code, 400)

    def test_api_scan(self):
        r = self.client.post("/api/v1/scan", json={"text": "mail a@b.io", "style": "label"})
        body = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(body["redacted_text"], "mail [EMAIL]")
        self.assertNotIn("value", body["findings"][0])
        r = self.client.post("/api/v1/scan", json={"text": "mail a@b.io", "include_values": True})
        self.assertEqual(r.get_json()["findings"][0]["value"], "a@b.io")

    def test_api_validation(self):
        post = lambda j: self.client.post("/api/v1/scan", json=j)  # noqa: E731
        self.assertEqual(post({}).status_code, 400)
        self.assertEqual(post({"text": "x", "style": "nope"}).status_code, 400)
        self.assertEqual(post({"text": "x", "detectors": ["nope"]}).status_code, 400)
        self.assertEqual(post({"text": "x" * 30000}).status_code, 413)
        self.assertEqual(self.client.post("/api/v1/scan", data="not json").status_code, 400)

    def test_rate_limit(self):
        app = create_app({"TESTING": True, "RATE_LIMIT_PER_MIN": 2})
        c = app.test_client()
        codes = [c.post("/api/v1/scan", json={"text": "x"}).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])


if __name__ == "__main__":
    unittest.main()
