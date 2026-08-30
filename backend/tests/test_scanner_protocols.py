import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from app.scanner import oui_lookup
from app.scanner.device_info import (
    BulkSSDPProtocol,
    DeviceInfoScanner,
    EnhancedDeviceInfo,
    HTTP_PORT_SCHEMES,
    MAX_RESPONSE_BYTES,
)


class FakeTransport:
    def __init__(self):
        self.sent = []
        self.closed = False

    def sendto(self, payload, address):
        self.sent.append((payload, address))

    def close(self):
        self.closed = True


class FakeContent:
    def __init__(self):
        self.read_size = None

    async def read(self, size):
        self.read_size = size
        return b"<html><title>Protected camera</title></html>"


class FakeResponse:
    status = 401
    charset = "utf-8"
    headers = {"Server": "camera-httpd", "WWW-Authenticate": "Basic"}

    def __init__(self):
        self.content = FakeContent()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class FakeClientSession:
    response = FakeResponse()

    def __init__(self, *_args, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def get(self, _url, **_kwargs):
        return self.response


class ScannerProtocolTests(unittest.IsolatedAsyncioTestCase):
    def test_ssdp_protocol_collects_and_deduplicates_multiple_hosts(self):
        protocol = BulkSSDPProtocol({"192.168.1.2", "192.168.1.3"})
        packet = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.2/device.xml\r\n\r\n"
        protocol.datagram_received(packet, ("192.168.1.2", 1900))
        protocol.datagram_received(packet, ("192.168.1.2", 1900))
        protocol.datagram_received(packet, ("192.168.1.99", 1900))

        self.assertEqual(len(protocol.responses["192.168.1.2"]), 1)
        self.assertNotIn("192.168.1.99", protocol.responses)

    async def test_bulk_ssdp_sends_one_multicast_search(self):
        scanner = DeviceInfoScanner(timeout=0.01)
        transport = FakeTransport()
        protocol = BulkSSDPProtocol({"192.168.1.2"})
        loop = asyncio.get_running_loop()
        with patch.object(loop, "create_datagram_endpoint", new=AsyncMock(return_value=(transport, protocol))):
            with patch("app.scanner.device_info.asyncio.sleep", new=AsyncMock()):
                result = await scanner._scan_ssdp_bulk({"192.168.1.2"})

        self.assertEqual(result, {})
        self.assertEqual(len(transport.sent), 1)
        self.assertTrue(transport.closed)

    def test_https_scheme_and_upnp_url_safety(self):
        scanner = DeviceInfoScanner()
        self.assertEqual(HTTP_PORT_SCHEMES[8443], "https")
        self.assertTrue(scanner._is_safe_device_url("http://192.168.1.2/device.xml", "192.168.1.2"))
        self.assertFalse(scanner._is_safe_device_url("http://example.com/device.xml", "192.168.1.2"))
        self.assertFalse(scanner._is_safe_device_url("http://192.168.1.3/device.xml", "192.168.1.2"))

    async def test_http_probe_keeps_non_200_metadata_and_bounds_body(self):
        scanner = DeviceInfoScanner()
        info = EnhancedDeviceInfo(ip_address="192.168.1.2", open_ports=[8443])
        FakeClientSession.response = FakeResponse()
        with patch("app.scanner.device_info.aiohttp.ClientSession", FakeClientSession):
            with patch("app.scanner.device_info.aiohttp.TCPConnector", return_value=None):
                await scanner._probe_http(info.ip_address, info)

        self.assertEqual(info.http_info["8443"]["scheme"], "https")
        self.assertEqual(info.http_info["8443"]["status"], 401)
        self.assertEqual(info.http_info["8443"]["title"], "Protected camera")
        self.assertEqual(FakeClientSession.response.content.read_size, MAX_RESPONSE_BYTES)


class OUILookupTests(unittest.TestCase):
    def test_longest_prefix_wins(self):
        original = oui_lookup._oui_cache
        try:
            oui_lookup._oui_cache = {"001122": "Broad", "001122DDE": "Specific"}
            self.assertEqual(oui_lookup.lookup_vendor("00:11:22:dd:ee:ff"), "Specific")
        finally:
            oui_lookup._oui_cache = original

    def test_private_mac_has_no_oui(self):
        self.assertIsNone(oui_lookup.lookup_vendor("aa:bb:cc:dd:ee:ff"))


if __name__ == "__main__":
    unittest.main()
