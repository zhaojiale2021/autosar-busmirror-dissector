# AUTOSAR BusMirror — Wireshark Dissector & Test Generator

Wireshark Lua dissector and Python test-packet generator for the AUTOSAR BusMirror serialization protocol (CP SWS BusMirroring R23-11 / R24-11).

## Overview

**BusMirror** is an AUTOSAR Basic Software module that replicates traffic and state of internal buses (CAN, LIN, FlexRay) to an external bus (Ethernet IP, CAN-FD, etc.) for diagnostics. The serialization protocol packs multiple source frames into a single destination frame.

This project provides:

| File | Purpose |
|------|---------|
| `autosar_busmirror.lua` | Wireshark Lua dissector — parses and displays BusMirror v1 packets |
| `sample_generator.py` | Test-packet generator — creates valid BusMirror packets for validation |

## Quick Start

### Wireshark Dissector

Copy the Lua script to Wireshark's plugin directory:

```
# Windows
copy autosar_busmirror.lua "C:\Program Files\Wireshark\plugins\"

# Linux / macOS
cp autosar_busmirror.lua ~/.local/lib/wireshark/plugins/
```

Or load it manually: **Analyze → Lua → Evaluate**.

The dissector registers on **UDP/TCP port 30490** (configurable in Preferences) and also includes a heuristic detector for automatic recognition on any port.

### Test Generator

```bash
# Show built-in examples
python sample_generator.py --help

# Hex dump to terminal (text2pcap compatible)
python sample_generator.py --hex --example mixed

# Generate PCAP file (requires scapy)
python sample_generator.py --pcap test.pcap --example can

# Generate all examples at once
python sample_generator.py --all --pcap all_examples.pcap
```

**Built-in examples:**

| Example | Description |
|---------|-------------|
| `can` | Standard CAN 2.0 frame, 11-bit ID 0x7FF, 8-byte payload |
| `can-fd` | CAN FD extended frame, 29-bit ID, 64-byte payload |
| `lin` | LIN frame, PID 0x3C, 8-byte payload |
| `flexray` | FlexRay frame, Slot 42, Cycle 15, Channel A |
| `ethernet` | Ethernet frame, Controller 1, VLAN 100 |
| `mixed` | All bus types + state-only + frameID-only edge cases (7 items) |

### Import into Wireshark

```bash
# From hex dump
python sample_generator.py --hex --example mixed > packet.hex
text2pcap -l 147 packet.hex packet.pcap

# Direct PCAP (requires scapy)
pip install scapy
python sample_generator.py --pcap packet.pcap --example mixed
```

Open the `.pcap` file in Wireshark, right-click any packet → **Decode As** → select `AUTOSAR BusMirror`.

## Protocol Structure

```
┌──────────────────────────────────────────────────────────────┐
│ Header (14 bytes)                                            │
├──────┬──────┬─────────────────┬───────────────┬──────────────┤
│ Ver  │ Seq  │ Timestamp (10B) │ DataLength    │              │
│ uint8│ uint8│ 48-bit sec +    │ uint16 BE     │              │
│      │      │ 32-bit ns       │               │              │
└──────┴──────┴─────────────────┴───────────────┴──────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ Data Item (variable, repeated)                               │
├──────────┬───────┬───────────┬─────────────┬─────────────────┤
│ RelTs    │ Flags │ NetworkID │ [NetState]  │ [FrameID]       │
│ uint16 BE│ uint8 │ uint8     │ uint8       │ var (1/3/4 B)   │
├──────────┴───────┴───────────┴─────────────┴─────────────────┤
│ [PayloadLen]   │ [Payload]                                   │
│ var (1/2 B)    │ bytes                                       │
└────────────────┴─────────────────────────────────────────────┘
```

### Supported Network Types

| Type | FrameID Size | PayloadLen Size | Status |
|------|-------------|-----------------|--------|
| CAN (1) | 4 bytes | 1 byte (uint8) | Full support — IDE, FDF, 11/29-bit ID, NetworkState |
| LIN (2) | 1 byte | 1 byte (uint8) | Full support — PID, parity, unconditional ID, NetworkState |
| FlexRay (3) | 3 bytes | 1 byte (uint8) | Full support — Channel A/B, Slot ID, Cycle, NetworkState |
| Ethernet (4) | 4 bytes | 1 byte (uint8) | Controller/Port ID + VLAN ID |
| Custom (16–31) | 4 bytes (default) | 1 byte | Raw display |

## Known Limitations

- Only the **serialization protocol** (`MirroringProtocolEnum=version1`) is supported — i.e. FlexRay / Ethernet / CDD destinations. The CAN 2.0 destination ID-mapping mode (`MirroringProtocolEnum=none`) is not supported.
- The Ethernet FrameID layout (4 bytes: Controller/Port ID + VLAN ID) is a best-effort interpretation based on AUTOSAR conventions. Exact layouts may vary between implementations.
- No fragmentation/reassembly of mirrored source frames.

## Documentation

- [中文版 (Chinese)](README_zh.md)

## Specification Reference

- **AUTOSAR CP SWS BusMirroring** — [R23-11](https://www.autosar.org/fileadmin/standards/R23-11/CP/AUTOSAR_CP_SWS_BusMirroring.pdf) / [R24-11](https://www.autosar.org/fileadmin/standards/R24-11/CP/AUTOSAR_CP_SWS_BusMirroring.pdf)
- **AUTOSAR CP TPS SystemTemplate** — [R24-11](https://www.autosar.org/fileadmin/standards/R24-11/CP/AUTOSAR_CP_TPS_SystemTemplate.pdf) (BusMirror section)

## Requirements

- **Wireshark** ≥ 3.0 (Lua 5.2+)
- **Python** ≥ 3.7 (generator only)
- **scapy** (optional, for PCAP output: `pip install scapy`)

## License

MIT
