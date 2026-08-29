import json
import unittest
from datetime import datetime, timezone

from app.db.models import Device
from app.scanner.arp_scanner import DiscoveredDevice
from app.scanner.network_scanner import NetworkScanner


class FakeSession:
    def __init__(self):
        self.deleted = []

    async def execute(self, _statement):
        return None

    async def delete(self, device):
        self.deleted.append(device)


class RotatingMacTests(unittest.TestCase):
    def setUp(self):
        self.scanner = NetworkScanner()

    @staticmethod
    def device(device_id, mac, *, ip="192.168.1.20", hostname=None, online=True, known=True, aliases=None):
        return Device(
            id=device_id,
            mac_address=mac,
            ip_address=ip,
            hostname=hostname,
            is_online=online,
            is_known=known,
            mac_aliases=json.dumps(aliases or []),
        )

    def test_private_mac_and_rotation_flags(self):
        device = self.device(
            1,
            "0a:bb:cc:dd:ee:ff",
            aliases=["44:da:30:52:2d:30"],
        )

        self.assertTrue(device.is_private_mac)
        self.assertTrue(device.mac_rotation_detected)
        self.assertFalse(self.scanner._is_private_mac("03:bb:cc:dd:ee:ff"))

    def test_first_private_mac_matches_active_known_device_by_ip(self):
        known_device = self.device(
            7,
            "44:da:30:52:2d:30",
            hostname="FloiPhone",
        )
        discovered = DiscoveredDevice(
            mac_address="0a:bb:cc:dd:ee:ff",
            ip_address="192.168.1.20",
        )

        match = self.scanner._find_rotating_mac_match(
            discovered,
            None,
            [known_device],
            set(),
        )

        self.assertIs(match, known_device)

    def test_existing_unknown_private_row_can_find_known_record_by_hostname(self):
        unknown_private_row = self.device(
            26,
            "b6:95:2b:e1:ae:d0",
            ip="192.168.1.22",
            hostname="iPhone de Florent",
            known=False,
        )
        known_device = self.device(
            25,
            "60:f4:45:d9:8e:54",
            ip="192.168.1.26",
            hostname="iPhone de Florent",
            online=False,
            known=True,
        )
        discovered = DiscoveredDevice(
            mac_address=unknown_private_row.mac_address,
            ip_address=unknown_private_row.ip_address,
        )

        match = self.scanner._find_rotating_mac_match(
            discovered,
            None,
            [unknown_private_row, known_device],
            {unknown_private_row.id},
            identity_hint=unknown_private_row,
        )

        self.assertIs(match, known_device)

    def test_ambiguous_same_ip_is_not_auto_merged(self):
        devices = [
            self.device(1, "44:da:30:52:2d:30"),
            self.device(2, "dc:52:85:05:c3:1c"),
        ]
        discovered = DiscoveredDevice(
            mac_address="0a:bb:cc:dd:ee:ff",
            ip_address="192.168.1.20",
        )

        match = self.scanner._find_rotating_mac_match(discovered, None, devices, set())

        self.assertIsNone(match)

    def test_alias_lookup_accepts_common_mac_formats(self):
        device = self.device(
            1,
            "44:da:30:52:2d:30",
            aliases=["AABB.CCDD.EEFF"],
        )

        lookup = self.scanner._device_lookup([device])

        self.assertIs(lookup["aa:bb:cc:dd:ee:ff"], device)
        self.assertEqual(self.scanner._normalise_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")

    def test_merge_preserves_known_record_and_history(self):
        now = datetime.now(timezone.utc)
        source = self.device(
            26,
            "b6:95:2b:e1:ae:d0",
            hostname="iPhone de Florent",
            known=False,
            aliases=["02:11:22:33:44:55"],
        )
        source.first_seen = now
        target = self.device(
            25,
            "60:f4:45:d9:8e:54",
            hostname="iPhone de Florent",
            known=True,
        )
        target.first_seen = now
        target.is_favorite = True
        session = FakeSession()

        import asyncio
        asyncio.run(self.scanner._merge_device_records(source, target, session))

        self.assertTrue(target.is_favorite)
        self.assertIn("60:f4:45:d9:8e:54", json.loads(target.mac_aliases))
        self.assertIn("b6:95:2b:e1:ae:d0", json.loads(target.mac_aliases))
        self.assertIn(source, session.deleted)


if __name__ == "__main__":
    unittest.main()
