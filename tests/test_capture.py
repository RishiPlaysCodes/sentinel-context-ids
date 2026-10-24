import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, wrpcap
from sentinel.capture import read_capture
from sentinel.features import extract_features


def capture(tmp_path):
    packets = []
    for i, flags in enumerate(["S", "SA", "A", "RA"]):
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / TCP(sport=40000, dport=443, flags=flags)
            / Raw(b"x" * 20)
        )
        packet.time = 1700000000 + i
        packets.append(packet)
    udp = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=40001, dport=53)
        / Raw(b"x" * 10)
    )
    udp.time = 1700000005
    packets.append(udp)
    path = tmp_path / "test.pcap"
    wrpcap(str(path), packets)
    return path


def test_exact_offline_packet_counts_and_unknown_auth(tmp_path):
    flows, quality = read_capture(capture(tmp_path))
    tcp = flows.loc[flows.protocol == "TCP"].iloc[0]
    assert (
        tcp.packets == 4
        and tcp.syn_count == 2
        and tcp.ack_count == 3
        and tcp.rst_count == 1
    )
    assert tcp.flow_duration_s == 3
    assert (flows.auth_available == 0).all()
    assert quality["packets_read"] == 5 and quality["flows"] == 2
    extract_features(flows)


def test_limit_is_visible_and_requires_review(tmp_path, detector):
    flows, quality = read_capture(capture(tmp_path), max_packets=2)
    assert quality["limit_reached"] and flows.capture_incomplete.all()
    result = detector.predict(flows)
    assert result.review_reasons.str.contains("capture_incomplete").all()


def test_invalid_capture_has_clear_error(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_text("not a capture")
    with pytest.raises(ValueError, match="Cannot open capture"):
        read_capture(path)
