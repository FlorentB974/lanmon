import unittest

from app.db.models import Device
from app.scanner.fingerprint import FingerprintClassifier, FingerprintInput


class FingerprintClassifierTests(unittest.TestCase):
    def setUp(self):
        self.classifier = FingerprintClassifier()

    def classify(self, **values):
        return self.classifier.classify(FingerprintInput(**values))

    def test_apple_oui_and_ios_pairing_port_is_high_confidence(self):
        result = self.classify(vendor="Apple, Inc.", open_ports=[62078])

        self.assertEqual(result["category"], "phone")
        self.assertEqual(result["label"], "Apple iPhone/iPad")
        self.assertEqual(result["confidence"], "high")
        self.assertEqual({item["source"] for item in result["evidence"]}, {"tcp", "oui"})

    def test_private_mac_ios_signal_does_not_invent_vendor(self):
        result = self.classify(open_ports=[62078])

        self.assertEqual(result["label"], "Apple iPhone/iPad")
        self.assertEqual(result["confidence"], "medium")
        self.assertNotIn("oui", {item["source"] for item in result["evidence"]})

    def test_airplay_macbook_is_not_apple_tv(self):
        result = self.classify(
            hostnames=["Florents-MacBook-Pro.local"],
            services=["Florent's MacBook Pro (_airplay._tcp.local.)"],
        )

        self.assertEqual(result["category"], "laptop")
        self.assertNotEqual(result["label"], "Apple TV")

    def test_component_vendors_stay_broad_and_low_confidence(self):
        cases = [
            ("LG Innotek", "LG networked device"),
            ("Espressif Inc.", "IoT device or embedded Wi-Fi module"),
            ("Shanghai High-Flying Electronics", "IoT device or embedded Wi-Fi module"),
            ("Amazon Technologies Inc.", "Amazon networked device"),
        ]
        for vendor, label in cases:
            with self.subTest(vendor=vendor):
                result = self.classify(vendor=vendor)
                self.assertEqual(result["label"], label)
                self.assertEqual(result["confidence"], "low")

    def test_explicit_model_beats_weaker_generic_service(self):
        result = self.classify(
            model="eufy HomeBase2 / T8010",
            services=["_airplay._tcp.local."],
        )

        self.assertEqual(result["label"], "Eufy smart-home hub")
        self.assertEqual(result["confidence"], "high")

    def test_close_conflicting_candidates_are_suppressed(self):
        result = self.classify(open_ports=[62078, 631])

        self.assertTrue(result["ambiguous"])
        self.assertIsNone(result["label"])

    def test_manual_type_remains_effective(self):
        device = Device(device_type="speaker")
        device.set_identification(self.classify(vendor="Amazon Technologies Inc."))

        self.assertEqual(device.effective_device_type, "speaker")


if __name__ == "__main__":
    unittest.main()
