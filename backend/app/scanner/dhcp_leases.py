"""Optional read-only DHCP lease enrichment.

Supported inputs are dnsmasq's five-column lease file and a normalized JSON
array. Lease data is never required for scanning and malformed entries are
reported without aborting a network scan.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
from typing import Iterable, Literal, Optional


def normalize_mac(value: str) -> str:
    compact = (value or "").strip().lower().replace(":", "").replace("-", "").replace(".", "")
    if len(compact) != 12 or any(character not in "0123456789abcdef" for character in compact):
        raise ValueError("invalid MAC address")
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def normalize_ipv4(value: str) -> str:
    address = ipaddress.ip_address((value or "").strip())
    if address.version != 4:
        raise ValueError("only IPv4 DHCP leases are supported")
    return str(address)


@dataclass(frozen=True)
class DHCPLease:
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    vendor_class: Optional[str] = None
    expires_at: Optional[datetime] = None

    def to_discovery_dict(self) -> dict:
        value = asdict(self)
        value["expires_at"] = self.expires_at.isoformat() if self.expires_at else None
        return value


@dataclass
class DHCPLeaseResult:
    leases: list[DHCPLease]
    diagnostics: list[str]

    def by_mac(self) -> dict[str, DHCPLease]:
        return {lease.mac_address: lease for lease in self.leases}


def _parse_expiry(value) -> Optional[datetime]:
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, (int, float)) or str(value).isdigit():
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _active(lease: DHCPLease, now: datetime) -> bool:
    return lease.expires_at is None or lease.expires_at >= now


def parse_dnsmasq_leases(text: str, now: Optional[datetime] = None) -> DHCPLeaseResult:
    now = now or datetime.now(timezone.utc)
    leases: list[DHCPLease] = []
    diagnostics: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            diagnostics.append(f"line {line_number}: expected at least four dnsmasq fields")
            continue
        try:
            lease = DHCPLease(
                expires_at=_parse_expiry(parts[0]),
                mac_address=normalize_mac(parts[1]),
                ip_address=normalize_ipv4(parts[2]),
                hostname=None if parts[3] in ("*", "-") else parts[3],
            )
            if _active(lease, now):
                leases.append(lease)
            else:
                diagnostics.append(f"line {line_number}: expired lease ignored")
        except (ValueError, OverflowError, OSError) as error:
            diagnostics.append(f"line {line_number}: {error}")
    return DHCPLeaseResult(leases=leases, diagnostics=diagnostics)


def parse_json_leases(text: str, now: Optional[datetime] = None) -> DHCPLeaseResult:
    now = now or datetime.now(timezone.utc)
    diagnostics: list[str] = []
    leases: list[DHCPLease] = []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        return DHCPLeaseResult([], [f"invalid JSON: {error.msg}"])
    if not isinstance(payload, list):
        return DHCPLeaseResult([], ["JSON lease input must be an array"])

    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            diagnostics.append(f"item {index}: expected an object")
            continue
        try:
            lease = DHCPLease(
                mac_address=normalize_mac(str(item["mac_address"])),
                ip_address=normalize_ipv4(str(item["ip_address"])),
                hostname=str(item["hostname"]) if item.get("hostname") else None,
                vendor_class=str(item["vendor_class"]) if item.get("vendor_class") else None,
                expires_at=_parse_expiry(item.get("expires_at")),
            )
            if _active(lease, now):
                leases.append(lease)
            else:
                diagnostics.append(f"item {index}: expired lease ignored")
        except (KeyError, ValueError, OverflowError, OSError) as error:
            diagnostics.append(f"item {index}: {error}")
    return DHCPLeaseResult(leases=leases, diagnostics=diagnostics)


def load_dhcp_leases(
    path: Optional[str],
    input_format: Literal["auto", "dnsmasq", "json"] = "auto",
) -> DHCPLeaseResult:
    if not path:
        return DHCPLeaseResult([], [])
    lease_path = Path(path)
    try:
        text = lease_path.read_text(encoding="utf-8")
    except OSError as error:
        return DHCPLeaseResult([], [f"could not read {lease_path}: {error}"])

    selected_format = input_format
    if selected_format == "auto":
        selected_format = "json" if text.lstrip().startswith("[") else "dnsmasq"
    return parse_json_leases(text) if selected_format == "json" else parse_dnsmasq_leases(text)
