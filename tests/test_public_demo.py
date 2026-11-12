import os
import unittest

# Force the hosted configuration before importing the Flask app.
os.environ["DEMO_ONLY"] = "1"
from web_app import app, REPORT_CACHE  # noqa: E402


class PublicDemoTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_health_check_reports_demo_only(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["demo_only"])

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers.get("Content-Security-Policy", ""))

    def test_demo_report_can_be_downloaded_without_disk_write(self):
        before = set(REPORT_CACHE.keys())
        response = self.client.post("/api/demo", json={})
        self.assertEqual(response.status_code, 200)
        report_id = response.get_json()["report_id"]
        self.assertIn(report_id, REPORT_CACHE)
        download = self.client.get(f"/api/report/{report_id}")
        self.assertEqual(download.status_code, 200)
        self.assertIn(b'"demo": true', download.data)
        self.assertEqual(set(REPORT_CACHE.keys()) - before, {report_id})

    def test_live_scan_endpoints_are_disabled(self):
        scan = self.client.post("/api/scan", json={"target": "127.0.0.1", "authorized": True})
        discover = self.client.post("/api/discover", json={"network": "127.0.0.1/32", "authorized": True})
        self.assertEqual(scan.status_code, 403)
        self.assertEqual(discover.status_code, 403)


if __name__ == "__main__":
    unittest.main()
