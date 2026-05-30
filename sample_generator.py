#!/usr/bin/env python3
"""
AUTOSAR BusMirror Protocol — Test Packet Generator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Generates valid BusMirror (version 1) test packets for validating
the Wireshark Lua dissector.

Based on AUTOSAR CP SWS BusMirroring R23-11 / R24-11.

Output formats:
  --raw       Raw binary file (.bin), one packet
  --hex       Hex dump to stdout (for text2pcap import)
  --pcap      PCAP file (requires scapy: pip install scapy)

Examples:
  # Single CAN packet, hex dump to console
  python sample_generator.py --hex

  # Generate a PCAP with mixed bus types
  python sample_generator.py --pcap mixed.pcap

  # Raw binary output
  python sample_generator.py --raw packet.bin
"""

import struct
import sys
import time
import argparse
from typing import List, Optional, Tuple

# =============================================================================
# Protocol constants
# =============================================================================

NET_TYPE = {
    "INVALID":  0,
    "CAN":      1,
    "LIN":      2,
    "FLEXRAY":  3,
    "ETHERNET": 4,
}

NET_TYPE_NAMES = {v: k for k, v in NET_TYPE.items() if k != "INVALID"}

# FrameID sizes per network type
FRAME_ID_SIZES = {
    1: 4,   # CAN
    2: 1,   # LIN
    3: 3,   # FlexRay
    4: 4,   # Ethernet
}

# PayloadLength field size per network type (per [SWS_Mirror_00110]: always 8 bits)
PAYLOAD_LEN_SIZE = 1  # uint8 for all network types


# =============================================================================
# Data item builder helpers
# =============================================================================

def build_flags(net_type: int, state_avail: bool, fid_avail: bool, payload_avail: bool) -> int:
    """Pack flags byte: [NState|FID|Payload|NetType(5)]"""
    flags = net_type & 0x1F
    if state_avail:
        flags |= 0x80
    if fid_avail:
        flags |= 0x40
    if payload_avail:
        flags |= 0x20
    return flags


def build_can_frame_id(can_id: int, is_extended: bool = False, is_fd: bool = False) -> bytes:
    """Build 4-byte FrameIDCAN.
    For standard 11-bit IDs the value sits in bits [10:0] of the 29-bit field.
    """
    if is_extended:
        full_29bit = can_id & 0x1FFFFFFF
    else:
        full_29bit = can_id & 0x7FF  # lower 11 bits only

    byte0 = (full_29bit >> 24) & 0x1F          # ID[28:24]
    if is_extended:
        byte0 |= 0x80  # IDE
    if is_fd:
        byte0 |= 0x40  # FDF

    byte1 = (full_29bit >> 16) & 0xFF          # ID[23:16]
    byte2 = (full_29bit >> 8) & 0xFF           # ID[15:8]
    byte3 = full_29bit & 0xFF                  # ID[7:0]

    return struct.pack(">BBBB", byte0, byte1, byte2, byte3)


def build_lin_frame_id(pid: int) -> bytes:
    """Build 1-byte FrameIDLIN (full PID)."""
    return struct.pack(">B", pid & 0xFF)


def build_flexray_frame_id(slot_id: int, cycle: int,
                           ch_a: bool = True, ch_b: bool = False,
                           slot_valid: bool = True) -> bytes:
    """Build 3-byte FrameIDFlexRay."""
    byte0 = (slot_id >> 8) & 0x07  # Slot ID[10:8]
    if ch_b:
        byte0 |= 0x80
    if ch_a:
        byte0 |= 0x40
    if slot_valid:
        byte0 |= 0x08
    byte1 = slot_id & 0xFF          # Slot ID[7:0]
    byte2 = cycle & 0xFF            # Cycle Number
    return struct.pack(">BBB", byte0, byte1, byte2)


def build_eth_frame_id(ctrl_id: int, vlan_id: int) -> bytes:
    """Build 4-byte FrameIDEth."""
    return struct.pack(">HH", ctrl_id & 0xFFFF, vlan_id & 0x0FFF)


def build_can_network_state(frames_lost: bool = False, bus_online: bool = True,
                            error_passive: bool = False, bus_off: bool = False,
                            tx_err_cnt_div8: int = 0) -> bytes:
    """Build 1-byte NetworkStateCAN."""
    val = tx_err_cnt_div8 & 0x0F
    if frames_lost:
        val |= 0x80
    if bus_online:
        val |= 0x40
    if error_passive:
        val |= 0x20
    if bus_off:
        val |= 0x10
    return struct.pack(">B", val)


def build_lin_network_state(frames_lost: bool = False, bus_online: bool = True,
                            hdr_tx_err: bool = False, tx_err: bool = False,
                            rx_err: bool = False, rx_no_resp: bool = False) -> bytes:
    """Build 1-byte NetworkStateLIN."""
    val = 0
    if frames_lost:
        val |= 0x80
    if bus_online:
        val |= 0x40
    if hdr_tx_err:
        val |= 0x08
    if tx_err:
        val |= 0x04
    if rx_err:
        val |= 0x02
    if rx_no_resp:
        val |= 0x01
    return struct.pack(">B", val)


def build_flexray_network_state(frames_lost: bool = False, bus_online: bool = True,
                                bus_sync: bool = True, normal_active: bool = True,
                                syntax_err: bool = False, content_err: bool = False,
                                boundary_viol: bool = False, tx_conflict: bool = False) -> bytes:
    """Build 1-byte NetworkStateFlexRay."""
    val = 0
    if frames_lost:
        val |= 0x80
    if bus_online:
        val |= 0x40
    if bus_sync:
        val |= 0x20
    if normal_active:
        val |= 0x10
    if syntax_err:
        val |= 0x08
    if content_err:
        val |= 0x04
    if boundary_viol:
        val |= 0x02
    if tx_conflict:
        val |= 0x01
    return struct.pack(">B", val)


# =============================================================================
# Data item structure
# =============================================================================

class DataItem:
    """One mirrored frame inside a BusMirror packet."""

    def __init__(self, net_type: int, net_id: int,
                 rel_timestamp: int = 0,
                 include_state: bool = False,
                 include_frame_id: bool = True,
                 include_payload: bool = True):
        self.net_type = net_type
        self.net_id = net_id
        self.rel_timestamp = rel_timestamp  # in 10us units

        # NetworkState callbacks (set per-type below)
        self.network_state: Optional[bytes] = None
        self.frame_id: Optional[bytes] = None
        self.payload: bytes = b""

        self.include_state = include_state
        self.include_frame_id = include_frame_id
        self.include_payload = include_payload

    def set_can(self, can_id: int, is_extended: bool = False, is_fd: bool = False,
                payload: bytes = b"",
                frames_lost: bool = False, bus_online: bool = True,
                error_passive: bool = False, bus_off: bool = False,
                tx_err_cnt_div8: int = 0):
        """Configure as a CAN frame."""
        self.net_type = NET_TYPE["CAN"]
        self.frame_id = build_can_frame_id(can_id, is_extended, is_fd)
        self.payload = payload
        if self.include_state:
            self.network_state = build_can_network_state(
                frames_lost, bus_online, error_passive, bus_off, tx_err_cnt_div8)

    def set_lin(self, pid: int, payload: bytes = b"",
                frames_lost: bool = False, bus_online: bool = True,
                hdr_tx_err: bool = False, tx_err: bool = False,
                rx_err: bool = False, rx_no_resp: bool = False):
        """Configure as a LIN frame."""
        self.net_type = NET_TYPE["LIN"]
        self.frame_id = build_lin_frame_id(pid)
        self.payload = payload
        if self.include_state:
            self.network_state = build_lin_network_state(
                frames_lost, bus_online, hdr_tx_err, tx_err, rx_err, rx_no_resp)

    def set_flexray(self, slot_id: int, cycle: int,
                    ch_a: bool = True, ch_b: bool = False,
                    slot_valid: bool = True,
                    payload: bytes = b"",
                    frames_lost: bool = False, bus_online: bool = True,
                    bus_sync: bool = True, normal_active: bool = True,
                    syntax_err: bool = False, content_err: bool = False,
                    boundary_viol: bool = False, tx_conflict: bool = False):
        """Configure as a FlexRay frame."""
        self.net_type = NET_TYPE["FLEXRAY"]
        self.frame_id = build_flexray_frame_id(slot_id, cycle, ch_a, ch_b, slot_valid)
        self.payload = payload
        if self.include_state:
            self.network_state = build_flexray_network_state(
                frames_lost, bus_online, bus_sync, normal_active,
                syntax_err, content_err, boundary_viol, tx_conflict)

    def set_ethernet(self, ctrl_id: int, vlan_id: int, payload: bytes = b""):
        """Configure as an Ethernet frame (source port + VLAN info)."""
        self.net_type = NET_TYPE["ETHERNET"]
        self.frame_id = build_eth_frame_id(ctrl_id, vlan_id)
        self.payload = payload

    def serialize(self) -> bytes:
        """Serialize this data item to bytes."""
        buf = b""

        # Relative Timestamp (uint16 BE, 10µs units)
        buf += struct.pack(">H", self.rel_timestamp & 0xFFFF)

        # Flags
        has_state = self.include_state and self.network_state is not None
        has_fid = self.include_frame_id and self.frame_id is not None
        has_payload = self.include_payload and len(self.payload) > 0
        flags = build_flags(self.net_type, has_state, has_fid, has_payload)
        buf += struct.pack(">B", flags)

        # Network ID
        buf += struct.pack(">B", self.net_id & 0xFF)

        # Optional: NetworkState
        if has_state:
            buf += self.network_state

        # Optional: FrameID
        if has_fid:
            buf += self.frame_id

        # Optional: PayloadLength + Payload
        if has_payload:
            plen = len(self.payload)
            buf += struct.pack(">B", plen)    # uint8 per [SWS_Mirror_00110]
            buf += self.payload

        return buf

    def describe(self) -> str:
        """Human-readable description of this data item."""
        nt = NET_TYPE_NAMES.get(self.net_type, f"Unknown({self.net_type})")
        parts = [f"  {nt} (NetID={self.net_id}) rel_ts={self.rel_timestamp}"]
        if self.network_state:
            parts.append(f"    NetworkState: {self.network_state.hex()}")
        if self.frame_id:
            parts.append(f"    FrameID:      {self.frame_id.hex()}")
        if self.payload:
            parts.append(f"    Payload:      {len(self.payload)}B {self.payload.hex()}")
        return "\n".join(parts)


# =============================================================================
# BusMirror Packet
# =============================================================================

class BusMirrorPacket:
    """A complete BusMirror version 1 packet."""

    def __init__(self, sequence_number: int = 0):
        self.version = 1
        self.sequence = sequence_number & 0xFF
        self.items: List[DataItem] = []

        # Timestamp: seconds since Unix epoch, nanoseconds fraction
        now = time.time()
        self.seconds = int(now)
        self.nanos = int((now - int(now)) * 1e9)

    def add(self, item: DataItem) -> "BusMirrorPacket":
        self.items.append(item)
        return self

    def serialize(self) -> bytes:
        """Serialize the full BusMirror packet to bytes."""
        # Serialize all data items first to compute DataLength
        items_data = b"".join(item.serialize() for item in self.items)
        data_length = len(items_data)

        buf = b""
        # ProtocolVersion (uint8)
        buf += struct.pack(">B", self.version)
        # SequenceNumber (uint8)
        buf += struct.pack(">B", self.sequence)
        # Timestamp Seconds (uint48 BE) → stored as uint16 + uint32
        buf += struct.pack(">H", (self.seconds >> 32) & 0xFFFF)   # bits 47..32
        buf += struct.pack(">I", self.seconds & 0xFFFFFFFF)        # bits 31..0
        # Timestamp Nanoseconds (uint32 BE)
        buf += struct.pack(">I", self.nanos & 0xFFFFFFFF)
        # DataLength (uint16 BE)
        buf += struct.pack(">H", data_length & 0xFFFF)
        # Data Items
        buf += items_data

        return buf

    def describe(self) -> str:
        """Human-readable summary."""
        lines = [
            f"BusMirror v{self.version}  Seq={self.sequence}",
            f"Timestamp: {self.seconds}.{self.nanos:09d}",
            f"DataLength: {sum(len(it.serialize()) for it in self.items)} bytes",
            f"Data Items ({len(self.items)}):",
        ]
        for i, item in enumerate(self.items):
            lines.append(f"--- Item #{i + 1} ---")
            lines.append(item.describe())
        lines.append("")
        lines.append(f"Total packet: {14 + sum(len(it.serialize()) for it in self.items)} bytes")
        return "\n".join(lines)


# =============================================================================
# Pre-built example packets
# =============================================================================

def make_can_only_packet() -> BusMirrorPacket:
    """Single CAN frame: standard 11-bit ID 0x7FF, 8-byte payload."""
    pkt = BusMirrorPacket(sequence_number=1)
    item = DataItem(NET_TYPE["CAN"], net_id=0, rel_timestamp=100)
    item.set_can(can_id=0x7FF, is_extended=False, is_fd=False,
                 payload=b"\x11\x22\x33\x44\x55\x66\x77\x88",
                 bus_online=True, error_passive=False)
    pkt.add(item)
    return pkt


def make_can_fd_extended_packet() -> BusMirrorPacket:
    """Single CAN FD extended frame: 29-bit ID 0x1ABCDEF, 64-byte payload."""
    pkt = BusMirrorPacket(sequence_number=2)
    item = DataItem(NET_TYPE["CAN"], net_id=0, rel_timestamp=200)
    item.set_can(can_id=0x1ABCDEF, is_extended=True, is_fd=True,
                 payload=bytes(range(64)),
                 bus_online=True, error_passive=False)
    pkt.add(item)
    return pkt


def make_lin_packet() -> BusMirrorPacket:
    """Single LIN frame: PID=0x3C (ID=0x0C), 8-byte payload."""
    pkt = BusMirrorPacket(sequence_number=3)
    item = DataItem(NET_TYPE["LIN"], net_id=1, rel_timestamp=50)
    item.set_lin(pid=0x3C, payload=b"\x01\x02\x03\x04\x05\x06\x07\x08",
                 bus_online=True)
    pkt.add(item)
    return pkt


def make_flexray_packet() -> BusMirrorPacket:
    """Single FlexRay frame: Slot 42, Cycle 15, Channel A, 16-byte payload."""
    pkt = BusMirrorPacket(sequence_number=4)
    item = DataItem(NET_TYPE["FLEXRAY"], net_id=0, rel_timestamp=300)
    item.set_flexray(slot_id=42, cycle=15, ch_a=True, ch_b=False,
                     payload=b"\xAA" * 16,
                     bus_online=True, bus_sync=True, normal_active=True)
    pkt.add(item)
    return pkt


def make_ethernet_packet() -> BusMirrorPacket:
    """Single Ethernet frame: Controller 1, VLAN 100, 32-byte payload."""
    pkt = BusMirrorPacket(sequence_number=5)
    item = DataItem(NET_TYPE["ETHERNET"], net_id=0, rel_timestamp=150)
    item.set_ethernet(ctrl_id=1, vlan_id=100, payload=bytes(range(32)))
    pkt.add(item)
    return pkt


def make_mixed_packet() -> BusMirrorPacket:
    """Mixed packet with all 4 bus types + state changes."""
    pkt = BusMirrorPacket(sequence_number=10)
    pkt.seconds = 0x123456789AB  # distinct 48-bit timestamp
    pkt.nanos = 123456789

    # CAN standard ID 0x123 with state
    can_item = DataItem(NET_TYPE["CAN"], net_id=0, rel_timestamp=10,
                        include_state=True)
    can_item.set_can(can_id=0x123, is_extended=False, is_fd=False,
                     payload=b"\xDE\xAD\xBE\xEF",
                     bus_online=True, error_passive=True, tx_err_cnt_div8=12)
    pkt.add(can_item)

    # LIN with state
    lin_item = DataItem(NET_TYPE["LIN"], net_id=1, rel_timestamp=25,
                        include_state=True)
    lin_item.set_lin(pid=0x2A, payload=b"\x01\x02\x03",
                     bus_online=True, rx_err=True)
    pkt.add(lin_item)

    # FlexRay with state
    fr_item = DataItem(NET_TYPE["FLEXRAY"], net_id=0, rel_timestamp=50,
                       include_state=True)
    fr_item.set_flexray(slot_id=100, cycle=31, ch_a=True, ch_b=True,
                        payload=b"\xFF" * 8,
                        bus_online=True, bus_sync=True, normal_active=True,
                        syntax_err=False)
    pkt.add(fr_item)

    # CAN FD extended with state
    canfd_item = DataItem(NET_TYPE["CAN"], net_id=1, rel_timestamp=80,
                          include_state=True)
    canfd_item.set_can(can_id=0x1AABBCC, is_extended=True, is_fd=True,
                       payload=bytes([i * 3 for i in range(48)]),
                       bus_online=True)
    pkt.add(canfd_item)

    # Ethernet
    eth_item = DataItem(NET_TYPE["ETHERNET"], net_id=0, rel_timestamp=120)
    eth_item.set_ethernet(ctrl_id=2, vlan_id=200,
                          payload=b"\x00\x01\x02\x03\x04\x05\x06\x07")
    pkt.add(eth_item)

    # State-only item (no FrameID, no Payload — just a state change notification)
    state_only = DataItem(NET_TYPE["CAN"], net_id=0, rel_timestamp=150,
                          include_state=True, include_frame_id=False,
                          include_payload=False)
    state_only.network_state = build_can_network_state(
        frames_lost=True, bus_online=False, bus_off=True)
    pkt.add(state_only)

    # FrameID-only item (no payload, no state)
    fid_only = DataItem(NET_TYPE["CAN"], net_id=2, rel_timestamp=180,
                        include_state=False, include_frame_id=True,
                        include_payload=False)
    fid_only.set_can(can_id=0x555, is_extended=False)
    pkt.add(fid_only)

    return pkt


# =============================================================================
# Output functions
# =============================================================================

def write_hex_dump(pkt: BusMirrorPacket, file=sys.stdout):
    """Print hex dump suitable for text2pcap import."""
    raw = pkt.serialize()
    print(f"# {pkt.describe().replace(chr(10), chr(10) + '# ')}", file=file)
    print(file=file)
    # text2pcap format: offset: hex bytes
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        print(f"{i:06X}: {hex_str}", file=file)
    print(file=file)
    print(f"# text2pcap hint:", file=file)
    print(f"#   text2pcap -l 147 output.hex output.pcap", file=file)
    return raw


def write_raw_binary(pkt: BusMirrorPacket, path: str):
    """Write raw BusMirror bytes to a binary file."""
    raw = pkt.serialize()
    with open(path, "wb") as f:
        f.write(raw)
    print(f"Wrote {len(raw)} bytes to {path}")
    print()
    print(pkt.describe())


def write_pcap(pkt: BusMirrorPacket, path: str, src_port: int = 12345, dst_port: int = 30490):
    """Write BusMirror packet wrapped in UDP/IP/Ethernet to a PCAP file.

    Requires scapy: pip install scapy
    """
    try:
        from scapy.all import (
            Ether, IP, UDP, Raw,
            wrpcap
        )
    except ImportError:
        print("ERROR: scapy is required for PCAP output.", file=sys.stderr)
        print("Install it with: pip install scapy", file=sys.stderr)
        print("", file=sys.stderr)
        print("Falling back to raw binary output...", file=sys.stderr)
        write_raw_binary(pkt, path.replace(".pcap", ".bin").replace(".pcapng", ".bin"))
        return

    raw = pkt.serialize()

    pcap_pkt = (
        Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee") /
        IP(src="192.168.1.100", dst="192.168.1.200") /
        UDP(sport=src_port, dport=dst_port) /
        Raw(load=raw)
    )

    wrpcap(path, [pcap_pkt])
    print(f"Wrote {len(raw)}-byte BusMirror packet → {path}")
    print(f"  UDP {src_port} → {dst_port}")
    print()
    print(pkt.describe())


def write_multipacket_pcap(packets: List[BusMirrorPacket], path: str,
                           src_port: int = 12345, dst_port: int = 30490):
    """Write multiple BusMirror packets to a single PCAP file."""
    try:
        from scapy.all import (
            Ether, IP, UDP, Raw,
            wrpcap
        )
    except ImportError:
        print("ERROR: scapy is required for PCAP output.", file=sys.stderr)
        print("Install it with: pip install scapy", file=sys.stderr)
        return

    pcap_pkts = []
    for pkt in packets:
        raw = pkt.serialize()
        pcap_pkts.append(
            Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee") /
            IP(src="192.168.1.100", dst="192.168.1.200") /
            UDP(sport=src_port, dport=dst_port) /
            Raw(load=raw)
        )

    wrpcap(path, pcap_pkts)
    print(f"Wrote {len(packets)} BusMirror packet(s) → {path}")
    print(f"  UDP {src_port} → {dst_port}")
    for i, pkt in enumerate(packets):
        print(f"\n--- Packet #{i + 1} ---")
        print(pkt.describe())


# =============================================================================
# CLI
# =============================================================================

EXAMPLES = {
    "can":           ("Single CAN standard frame",         make_can_only_packet),
    "can-fd":        ("Single CAN FD extended frame",      make_can_fd_extended_packet),
    "lin":           ("Single LIN frame",                  make_lin_packet),
    "flexray":       ("Single FlexRay frame",              make_flexray_packet),
    "ethernet":      ("Single Ethernet frame",             make_ethernet_packet),
    "mixed":         ("All bus types + state/edge cases",  make_mixed_packet),
}


def main():
    parser = argparse.ArgumentParser(
        description="AUTOSAR BusMirror test packet generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  " + "\n  ".join(
            f"{k:12s}  {v[0]}" for k, v in EXAMPLES.items()
        ) + "\n\nUsage:\n"
            "  %(prog)s --hex --example mixed\n"
            "  %(prog)s --pcap test.pcap --example can\n"
            "  %(prog)s --pcap all.pcap --all"
    )

    parser.add_argument("--example", choices=list(EXAMPLES.keys()),
                        default="mixed",
                        help="Which example packet to generate (default: mixed)")
    parser.add_argument("--all", action="store_true",
                        help="Generate all example packets (for --pcap output)")
    parser.add_argument("--hex", action="store_true",
                        help="Print hex dump to stdout (for text2pcap)")
    parser.add_argument("--raw", metavar="FILE",
                        help="Write raw binary to FILE")
    parser.add_argument("--pcap", metavar="FILE",
                        help="Write PCAP file (requires scapy)")
    parser.add_argument("--pcap-src-port", type=int, default=12345,
                        help="UDP source port for PCAP (default: 12345)")
    parser.add_argument("--pcap-dst-port", type=int, default=30490,
                        help="UDP destination port for PCAP (default: 30490)")
    parser.add_argument("--all-src-port", type=int, default=12345,
                        help="UDP src port for --all PCAP (default: 12345)")
    parser.add_argument("--all-dst-port", type=int, default=30490,
                        help="UDP dst port for --all PCAP (default: 30490)")

    args = parser.parse_args()

    # --all mode: generate every example
    if args.all:
        pkts = [fn() for _name, fn in EXAMPLES.values()]
        if args.pcap:
            write_multipacket_pcap(pkts, args.pcap,
                                   args.all_src_port, args.all_dst_port)
        elif args.raw:
            # Write each to a separate file
            base = args.raw.replace(".bin", "")
            for (name, _), pkt in zip(EXAMPLES.items(), pkts):
                path = f"{base}_{name}.bin"
                write_raw_binary(pkt, path)
        else:
            for (name, _), pkt in zip(EXAMPLES.items(), pkts):
                print(f"=== {name} ===")
                write_hex_dump(pkt)
                print()
        return

    # Single example mode
    pkt = EXAMPLES[args.example][1]()

    if args.hex:
        write_hex_dump(pkt)
    elif args.pcap:
        write_pcap(pkt, args.pcap, args.pcap_src_port, args.pcap_dst_port)
    elif args.raw:
        write_raw_binary(pkt, args.raw)
    else:
        # Default: hex dump
        write_hex_dump(pkt)


if __name__ == "__main__":
    main()
