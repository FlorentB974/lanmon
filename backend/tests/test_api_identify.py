import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.api.routes import identify_device, rescan_device
from app.scanner.network_scanner import IdentificationCooldownError


class FakeScanner:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    async def identify_device(self, device_id):
        self.calls.append(device_id)
        if self.error:
            raise self.error
        return self.result


class IdentifyRouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_identify_and_legacy_rescan_use_same_scanner_path(self):
        scanner = FakeScanner(result={"id": 7})
        with patch("app.main.scanner", scanner):
            self.assertEqual(await identify_device(7), {"id": 7})
            self.assertEqual(await rescan_device(7), {"id": 7})

        self.assertEqual(scanner.calls, [7, 7])

    async def test_cooldown_maps_to_429(self):
        scanner = FakeScanner(error=IdentificationCooldownError("wait"))
        with patch("app.main.scanner", scanner):
            with self.assertRaises(HTTPException) as raised:
                await identify_device(7)

        self.assertEqual(raised.exception.status_code, 429)
        self.assertIn("Retry-After", raised.exception.headers)


if __name__ == "__main__":
    unittest.main()
