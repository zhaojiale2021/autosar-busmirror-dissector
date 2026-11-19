# Capture and Dissector Validation

Use the bundled generator to create known-good packets when no vehicle capture is available.

## Generate a mixed packet capture

```bash
python -m pip install scapy
python sample_generator.py --pcap mixed.pcap --example mixed
```

The mixed example contains CAN, LIN, FlexRay, Ethernet, state-only, frame-ID-only, and payload edge cases.

For text2pcap without Scapy:

```bash
python sample_generator.py --hex --example mixed > packet.hex
text2pcap -l 147 packet.hex mixed.pcap
```

## Load the dissector

1. Copy `autosar_busmirror.lua` to Wireshark's user plugin directory.
2. Open `mixed.pcap`.
3. Right-click a packet and choose **Decode As**.
4. Select `AUTOSAR BusMirror`.

The dissector also registers UDP/TCP port `30490` and includes heuristic detection.

## Suggested review

Check these fields in one capture:

| Field | Expected coverage |
|---|---|
| Header | version, sequence, timestamp, data length |
| CAN | standard/extended ID, FD flag, payload, network state |
| LIN | PID, payload, network state |
| FlexRay | channel, slot, cycle, payload, network state |
| Ethernet | controller/port and VLAN fields |
| Flags | state-only and frame-ID-only edge cases |

Save both the capture and a Wireshark screenshot showing the decoded fields. Keep screenshots free of customer, VIN, MAC, IP, and other vehicle-identifying data.
