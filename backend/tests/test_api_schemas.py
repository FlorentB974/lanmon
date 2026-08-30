import unittest
from datetime import datetime, timezone

from app.api.schemas import DeviceResponse
from app.db.models import Device


class DeviceSchemaTests(unittest.TestCase):
    def test_identification_is_serialized_as_typed_object(self):
        now = datetime.now(timezone.utc)
        device = Device(
            id=1,
            mac_address="44:da:30:52:2d:30",
            mac_aliases="[]",
            ip_address="192.168.1.20",
            device_type=None,
            is_online=True,
            is_favorite=False,
            is_known=False,
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
            last_deep_scan_at=now,
        )
        device.set_identification({
            "version": 1,
            "label": "Apple iPhone/iPad",
            "category": "phone",
            "confidence": "high",
            "score": 85,
            "ambiguous": False,
            "evidence": [{
                "source": "tcp",
                "summary": "iOS pairing service",
                "value": "62078",
                "strength": "strong",
            }],
            "probes": {"tcp": "responded"},
            "identified_at": now.isoformat(),
        })

        response = DeviceResponse.model_validate(device)

        self.assertEqual(response.identification.label, "Apple iPhone/iPad")
        self.assertEqual(response.effective_device_type, "phone")
        self.assertEqual(response.model_dump(mode="json")["last_deep_scan_at"], now.isoformat().replace("+00:00", "Z"))


if __name__ == "__main__":
    unittest.main()
