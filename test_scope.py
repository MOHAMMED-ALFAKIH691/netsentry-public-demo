import unittest
from web_scanner import ScanError, demo_assessment, validate_ip_target, validate_network

class ScopeTests(unittest.TestCase):
    def test_private_and_loopback_ip_allowed(self):
        self.assertEqual(validate_ip_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_ip_target("192.168.56.101"), "192.168.56.101")

    def test_public_ip_blocked(self):
        with self.assertRaises(ScanError):
            validate_ip_target("8.8.8.8")

    def test_large_network_blocked(self):
        with self.assertRaises(ScanError):
            validate_network("192.168.0.0/16")

    def test_private_network_allowed(self):
        self.assertEqual(validate_network("192.168.56.0/24"), "192.168.56.0/24")

    def test_demo_is_synthetic(self):
        data = demo_assessment()
        self.assertTrue(data["demo"])
        self.assertEqual(data["open_port_count"], 2)
        self.assertEqual(data["risk_level"], "MEDIUM")
        self.assertFalse(data["simulation"]["executed"])

if __name__ == "__main__":
    unittest.main()
