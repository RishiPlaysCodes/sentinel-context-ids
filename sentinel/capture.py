"""Offline PCAP/PCAPNG ingestion. Counts observable evidence; never infers failed passwords."""

from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
from .temporal import add_context


def read_capture(path, max_packets=200000, max_flows=50000):
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP

    if max_packets < 1 or max_flows < 1:
        raise ValueError("Capture limits must be positive.")
    flows = {}
    quality = {
        "packets_read": 0,
        "unsupported_packets": 0,
        "fragmented_packets": 0,
        "malformed_packets": 0,
        "wire_truncated_packets": 0,
        "limit_reached": False,
        "authentication_evidence": "unavailable",
        "duration_floor_seconds": 0.000001,
    }
    try:
        reader = PcapReader(str(path))
    except Exception as exc:
        raise ValueError(f"Cannot open capture: {exc}") from exc
    try:
        for index, packet in enumerate(reader):
            if index >= max_packets:
                quality["limit_reached"] = True
                break
            quality["packets_read"] += 1
            try:
                network = packet.getlayer(IP) or packet.getlayer(IPv6)
                transport = packet.getlayer(TCP) or packet.getlayer(UDP)
                if network is None or transport is None:
                    quality["unsupported_packets"] += 1
                    continue
                if packet.haslayer(IP) and (
                    int(network.frag) > 0 or int(network.flags) & 1
                ):
                    quality["fragmented_packets"] += 1
                    continue
                now = float(packet.time)
                protocol = "TCP" if packet.haslayer(TCP) else "UDP"
                # Directional five-tuples, split into fixed 60-second buckets; not a TCP reassembly engine.
                key = (
                    str(network.src),
                    str(network.dst),
                    int(transport.sport),
                    int(transport.dport),
                    protocol,
                    int(now // 60),
                )
                if key not in flows:
                    if len(flows) >= max_flows:
                        quality["limit_reached"] = True
                        break
                    flows[key] = dict(
                        first=now,
                        last=now,
                        packets=0,
                        bytes=0,
                        syn_count=0,
                        ack_count=0,
                        rst_count=0,
                    )
                value = flows[key]
                value["first"] = min(value["first"], now)
                value["last"] = max(value["last"], now)
                value["packets"] += 1
                value["bytes"] += len(bytes(network))
                if protocol == "TCP":
                    flags = int(transport.flags)
                    for field, bit in [
                        ("syn_count", 2),
                        ("ack_count", 16),
                        ("rst_count", 4),
                    ]:
                        value[field] += int(bool(flags & bit))
                wire_length = getattr(packet, "wirelen", None)
                if wire_length is not None and int(wire_length) > len(bytes(packet)):
                    quality["wire_truncated_packets"] += 1
            except (ValueError, TypeError, AttributeError, IndexError):
                quality["malformed_packets"] += 1
    finally:
        reader.close()
    if not flows:
        raise ValueError("Capture contains no supported complete TCP/UDP observations.")
    incomplete = bool(
        quality["limit_reached"]
        or quality["wire_truncated_packets"]
        or quality["malformed_packets"]
        or quality["fragmented_packets"]
    )
    rows = []
    for number, (key, value) in enumerate(flows.items()):
        src, dst, sport, dport, protocol, bucket = key
        first, last = value.pop("first"), value.pop("last")
        rows.append(
            dict(
                flow_id=f"capture-{number:06d}",
                timestamp=datetime.fromtimestamp(last, timezone.utc).isoformat(),
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                protocol=protocol,
                flow_duration_s=max(last - first, 0.000001),
                failed_logins=0,
                auth_available=0,
                capture_incomplete=incomplete,
                **value,
            )
        )
    frame = add_context(pd.DataFrame(rows))
    quality["flows"] = len(frame)
    quality["context_unit"] = (
        "directional observed five-tuple/bucket records, not unique TCP handshakes"
    )
    quality["limits"] = (
        "No payload inspection, retransmission deduplication, IP fragment reassembly, or authentication outcomes."
    )
    return frame, quality
