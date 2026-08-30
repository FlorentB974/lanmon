import json
import unittest
from datetime import datetime, timedelta, timezone

from app.scanner.dhcp_leases import parse_dnsmasq_leases, parse_json_leases


class DHCPLeaseTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 30, tzinfo=timezone.utc)
        self.future = int((self.now + timedelta(hours=1)).timestamp())
        self.past = int((self.now - timedelta(hours=1)).timestamp())

    def test_dnsmasq_parser_accepts_active_and_reports_bad_or_stale_rows(self):
        result = parse_dnsmasq_leases(
            f"{self.future} aa:bb:cc:dd:ee:ff 192.168.1.9 living-room 01:aa\n"
            f"{self.past} 00:11:22:33:44:55 192.168.1.10 old-device *\n"
            "not enough\n",
            now=self.now,
        )

        self.assertEqual(len(result.leases), 1)
        self.assertEqual(result.leases[0].hostname, "living-room")
        self.assertEqual(len(result.diagnostics), 2)

    def test_json_parser_supports_vendor_class(self):
        result = parse_json_leases(json.dumps([{
            "mac_address": "AA-BB-CC-DD-EE-FF",
            "ip_address": "192.168.1.9",
            "hostname": "Flo-iPhone",
            "vendor_class": "Apple",
            "expires_at": (self.now + timedelta(hours=1)).isoformat(),
        }]), now=self.now)

        self.assertEqual(result.leases[0].mac_address, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result.leases[0].vendor_class, "Apple")

    def test_json_parser_does_not_abort_on_malformed_items(self):
        result = parse_json_leases('[{"ip_address":"192.168.1.3"}, "bad"]', now=self.now)

        self.assertEqual(result.leases, [])
        self.assertEqual(len(result.diagnostics), 2)


if __name__ == "__main__":
    unittest.main()
