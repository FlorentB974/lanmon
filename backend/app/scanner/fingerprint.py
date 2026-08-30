"""Deterministic, explainable LAN device fingerprinting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional


@dataclass(frozen=True)
class Evidence:
    source: str
    summary: str
    value: str
    strength: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "summary": self.summary,
            "value": self.value,
            "strength": self.strength,
        }


@dataclass
class _Candidate:
    label: str
    category: str
    score: int = 0
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class FingerprintInput:
    vendor: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    friendly_name: Optional[str] = None
    hostnames: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    http_info: dict[str, Any] = field(default_factory=dict)
    upnp_info: dict[str, Any] = field(default_factory=dict)
    banners: dict[str, str] = field(default_factory=dict)
    dhcp_info: dict[str, Any] = field(default_factory=dict)
    probes: dict[str, str] = field(default_factory=dict)


class FingerprintClassifier:
    """Score high-value signals without claiming more than they reveal."""

    @staticmethod
    def _evidence(source: str, summary: str, value: Any, strength: str) -> Evidence:
        return Evidence(source, summary, str(value), strength)

    def classify(self, data: FingerprintInput) -> dict[str, Any]:
        candidates: dict[str, _Candidate] = {}

        def add(key: str, label: str, category: str, points: int, evidence: Evidence) -> None:
            candidate = candidates.setdefault(key, _Candidate(label=label, category=category))
            candidate.score += points
            if evidence not in candidate.evidence:
                candidate.evidence.append(evidence)

        vendor = " ".join(value for value in (data.manufacturer, data.vendor) if value).lower()
        names = " ".join([*data.hostnames, data.friendly_name or ""]).lower()
        model = (data.model or "").strip()
        model_lower = model.lower()
        services = " ".join(data.services).lower()
        ports = set(data.open_ports)
        dhcp_hostname = str(data.dhcp_info.get("hostname") or "")
        dhcp_vendor = str(data.dhcp_info.get("vendor_class") or "")
        combined_names = f"{names} {dhcp_hostname.lower()}"

        # Explicit model and hostname signatures are the most useful signals.
        model_rules = [
            (("iphone",), "apple_mobile", "Apple iPhone", "phone"),
            (("ipad",), "apple_tablet", "Apple iPad", "tablet"),
            (("macbook",), "apple_macbook", "Apple MacBook", "laptop"),
            (("appletv", "apple tv"), "apple_tv", "Apple TV", "tv"),
            (("homepod",), "apple_homepod", "Apple HomePod", "speaker"),
            (("synology", "diskstation"), "synology", "Synology NAS", "nas"),
            (("homebase", "eufy"), "eufy", "Eufy smart-home hub", "iot"),
            (("soundbar", "lg sn"), "soundbar", "LG soundbar", "speaker"),
            (("mss", "msg"), "meross", "Meross smart device", "iot"),
            (("nvr", "dhi-nvr"), "nvr", "Network video recorder", "camera"),
        ]
        for patterns, key, label, category in model_rules:
            if any(pattern in model_lower for pattern in patterns):
                add(key, label, category, 85, self._evidence("model", "Explicit product model", model, "strong"))

        name_rules = [
            ("iphone", "apple_mobile", "Apple iPhone", "phone"),
            ("ipad", "apple_tablet", "Apple iPad", "tablet"),
            ("macbook", "apple_macbook", "Apple MacBook", "laptop"),
            ("apple-tv", "apple_tv", "Apple TV", "tv"),
            ("appletv", "apple_tv", "Apple TV", "tv"),
            ("printer", "printer", "Network printer", "printer"),
        ]
        for pattern, key, label, category in name_rules:
            if pattern in combined_names:
                add(key, label, category, 70, self._evidence("hostname", "Descriptive network name", pattern, "strong"))

        if "_googlecast" in services:
            label, category, key = ("LG soundbar", "speaker", "soundbar") if "soundbar" in f"{model_lower} {services}" else ("Google Cast device", "tv", "googlecast")
            add(key, label, category, 60, self._evidence("mdns", "Google Cast service", "_googlecast._tcp", "strong"))
        if "_ipp" in services or "_printer" in services or "_pdl" in services:
            add("printer", "Network printer", "printer", 70, self._evidence("mdns", "Printing service", "IPP/DNS-SD", "strong"))
        if "_sonos" in services:
            add("sonos", "Sonos speaker", "speaker", 80, self._evidence("mdns", "Sonos service", "_sonos._tcp", "strong"))
        if "_hap" in services or "_homekit" in services or "_matter" in services:
            add("smart_home", "Smart-home device", "iot", 45, self._evidence("mdns", "Smart-home protocol", "HomeKit/Matter", "medium"))
        if "_smb" in services or "_afpovertcp" in services or "_nfs" in services:
            add("file_server", "File server / NAS", "nas", 55, self._evidence("mdns", "File-sharing service", "SMB/AFP/NFS", "medium"))
        # AirPlay is deliberately evidence for an Apple-capable device, not an
        # Apple TV: current Macs, phones, speakers and TVs can all advertise it.
        if "_airplay" in services or "_raop" in services:
            add("apple_generic", "AirPlay-capable device", "other", 25, self._evidence("mdns", "AirPlay service", "AirPlay/RAOP", "weak"))

        port_rules = [
            (62078, "apple_mobile", "Apple iPhone/iPad", "phone", 65, "iOS pairing service"),
            (9100, "printer", "Network printer", "printer", 60, "JetDirect printing"),
            (631, "printer", "Network printer", "printer", 55, "IPP printing"),
            (515, "printer", "Network printer", "printer", 55, "LPD printing"),
            (32400, "plex", "Plex media server", "server", 80, "Plex service"),
            (5001, "synology", "Synology NAS", "nas", 65, "Synology DSM HTTPS"),
            (1400, "sonos", "Sonos speaker", "speaker", 75, "Sonos control service"),
            (8060, "roku", "Roku media player", "tv", 75, "Roku ECP service"),
            (8123, "home_assistant", "Home Assistant server", "server", 75, "Home Assistant web service"),
            (37777, "nvr", "Camera or network video recorder", "camera", 65, "Dahua device service"),
            (7547, "router", "Router or network gateway", "router", 55, "CPE management service"),
        ]
        for port, key, label, category, points, summary in port_rules:
            if port in ports:
                add(key, label, category, points, self._evidence("tcp", summary, port, "strong" if points >= 65 else "medium"))
        if 554 in ports:
            add("camera", "Camera or media streamer", "camera", 35, self._evidence("tcp", "RTSP streaming service", 554, "medium"))
        if 8000 in ports:
            add("camera", "Camera or network video recorder", "camera", 45, self._evidence("tcp", "Common camera management port", 8000, "medium"))
        if 8008 in ports or 8009 in ports:
            add("googlecast", "Google Cast device", "tv", 40, self._evidence("tcp", "Google Cast control port", 8008 if 8008 in ports else 8009, "medium"))
        if 445 in ports and 3389 in ports:
            add("windows", "Windows computer", "computer", 65, self._evidence("tcp", "Windows sharing and remote desktop", "445 + 3389", "strong"))
        if 1883 in ports or 8883 in ports:
            add("mqtt_device", "IoT or automation device", "iot", 35, self._evidence("tcp", "MQTT messaging service", 1883 if 1883 in ports else 8883, "medium"))

        banner_text = " ".join(data.banners.values()).lower()
        if "synology" in banner_text:
            add("synology", "Synology NAS", "nas", 75, self._evidence("banner", "Synology service banner", "Synology", "strong"))
        if "hikvision" in banner_text or "dahua" in banner_text:
            add("camera", "Camera or network video recorder", "camera", 75, self._evidence("banner", "Camera vendor service banner", "Hikvision/Dahua", "strong"))

        http_text = str(data.http_info).lower()
        http_rules = [
            ("synology", "synology", "Synology NAS", "nas", 75),
            ("home assistant", "home_assistant", "Home Assistant server", "server", 75),
            ("plex", "plex", "Plex media server", "server", 75),
            ("unifi", "unifi", "Ubiquiti UniFi equipment", "router", 70),
            ("printer", "printer", "Network printer", "printer", 65),
            ("hikvision", "camera", "Camera or network video recorder", "camera", 75),
            ("dahua", "camera", "Camera or network video recorder", "camera", 75),
        ]
        for pattern, key, label, category, points in http_rules:
            if pattern in http_text:
                add(key, label, category, points, self._evidence("http", "Web interface signature", pattern, "strong"))
        if "router" in http_text or "gateway" in http_text:
            add("router", "Router or network gateway", "router", 55, self._evidence("http", "Gateway web interface", "router/gateway", "medium"))

        upnp_text = str(data.upnp_info).lower()
        if "internetgateway" in upnp_text:
            add("router", "Router or network gateway", "router", 70, self._evidence("upnp", "Internet gateway device type", "InternetGatewayDevice", "strong"))
        elif "mediarenderer" in upnp_text:
            add("media_renderer", "Network media renderer", "tv", 50, self._evidence("upnp", "Media renderer device type", "MediaRenderer", "medium"))

        if "apple" in vendor:
            if "apple_mobile" in candidates:
                add("apple_mobile", "Apple iPhone/iPad", "phone", 20, self._evidence("oui", "Apple network interface", data.manufacturer or data.vendor, "medium"))
            elif not any(key.startswith("apple_") for key in candidates):
                add("apple_generic", "Apple device", "other", 25, self._evidence("oui", "Apple network interface", data.manufacturer or data.vendor, "weak"))
        if "synology" in vendor:
            add("synology", "Synology NAS", "nas", 70, self._evidence("oui", "Synology network interface", data.manufacturer or data.vendor, "strong"))
        if any(value in vendor for value in ("dahua", "hikvision")):
            add("camera", "Camera or network video recorder", "camera", 70, self._evidence("oui", "Security-camera vendor", data.manufacturer or data.vendor, "strong"))
        if any(value in vendor for value in ("espressif", "high-flying", "ampak", "tuya")):
            add("iot_module", "IoT device or embedded Wi-Fi module", "iot", 25, self._evidence("oui", "Component-module vendor", data.manufacturer or data.vendor, "weak"))
        if "lg innotek" in vendor:
            add("lg_module", "LG networked device", "iot", 25, self._evidence("oui", "LG component vendor", data.manufacturer or data.vendor, "weak"))
        if "amazon" in vendor:
            add("amazon", "Amazon networked device", "iot", 25, self._evidence("oui", "Amazon network interface", data.manufacturer or data.vendor, "weak"))

        dhcp_value = f"{dhcp_hostname} {dhcp_vendor}".strip()
        dhcp_lower = dhcp_value.lower()
        if dhcp_value:
            if "iphone" in dhcp_lower:
                add("apple_mobile", "Apple iPhone", "phone", 60, self._evidence("dhcp", "DHCP hostname/vendor class", dhcp_value, "strong"))
            elif "ipad" in dhcp_lower:
                add("apple_tablet", "Apple iPad", "tablet", 60, self._evidence("dhcp", "DHCP hostname/vendor class", dhcp_value, "strong"))
            elif "android" in dhcp_lower:
                add("android", "Android phone or tablet", "phone", 55, self._evidence("dhcp", "DHCP vendor class", dhcp_value, "medium"))
            elif "msft" in dhcp_lower or "windows" in dhcp_lower:
                add("windows", "Windows computer", "computer", 55, self._evidence("dhcp", "DHCP vendor class", dhcp_value, "medium"))

        ordered = sorted(candidates.values(), key=lambda candidate: candidate.score, reverse=True)
        winner = ordered[0] if ordered else None
        ambiguous = bool(winner and len(ordered) > 1 and winner.score - ordered[1].score < 15)
        if not winner or winner.score < 20 or ambiguous:
            label = category = confidence = None
            score = winner.score if winner else 0
            evidence = winner.evidence if winner else []
        else:
            score = min(winner.score, 100)
            confidence = "high" if score >= 75 else "medium" if score >= 45 else "low"
            label, category, evidence = winner.label, winner.category, winner.evidence

        return {
            "version": 1,
            "label": label,
            "category": category,
            "confidence": confidence,
            "score": score,
            "ambiguous": ambiguous,
            "evidence": [item.to_dict() for item in evidence],
            "probes": dict(sorted(data.probes.items())),
            "identified_at": datetime.now(timezone.utc).isoformat(),
        }


fingerprint_classifier = FingerprintClassifier()
