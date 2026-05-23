# AUTOSAR BusMirror — Wireshark 解析器 & 测试数据生成器

基于 AUTOSAR CP SWS BusMirroring (R23-11 / R24-11) 规范的 BusMirror 串行化协议解析工具。

## 项目简介

**BusMirror** 是 AUTOSAR 基础软件模块，用于将内部总线（CAN、LIN、FlexRay）的流量和状态镜像到外部总线（以太网、CAN-FD 等），供诊断仪监控调试使用。串行化协议将多个源总线帧打包到一个目标帧中传输。

本项目提供：

| 文件 | 说明 |
|------|------|
| `autosar_busmirror.lua` | Wireshark Lua 解析器，解析并展示 BusMirror v1 数据包 |
| `sample_generator.py` | Python 测试数据包生成器，生成符合协议规范的测试数据 |

## 快速开始

### Wireshark 解析器

将 Lua 脚本复制到 Wireshark 插件目录：

```bash
# Windows
copy autosar_busmirror.lua "C:\Program Files\Wireshark\plugins\"

# Linux / macOS
cp autosar_busmirror.lua ~/.local/lib/wireshark/plugins/
```

或手动加载：**分析 → Lua → 评估**。

解析器默认注册在 **UDP/TCP 端口 30490**（可在偏好设置中修改），同时内置启发式检测器，可在任意端口自动识别 BusMirror 报文。

### 测试生成器

```bash
# 查看内置示例
python sample_generator.py --help

# 终端输出 hex 数据（兼容 text2pcap）
python sample_generator.py --hex --example mixed

# 生成 PCAP 文件（需安装 scapy）
pip install scapy
python sample_generator.py --pcap test.pcap --example can

# 一次性生成所有示例
python sample_generator.py --all --pcap all_examples.pcap
```

**内置示例：**

| 示例 | 说明 |
|------|------|
| `can` | CAN 2.0 标准帧，11位 ID 0x7FF，8字节负载 |
| `can-fd` | CAN FD 扩展帧，29位 ID，64字节负载 |
| `lin` | LIN 帧，PID 0x3C，8字节负载 |
| `flexray` | FlexRay 帧，Slot 42、Cycle 15、Channel A |
| `ethernet` | 以太网帧，Controller 1、VLAN 100 |
| `mixed` | 混合包：包含全部4种总线类型 + 纯状态通知 + 纯FrameID 等边界情况（7个数据项） |

### 导入 Wireshark

```bash
# 方式一：从 hex 导入
python sample_generator.py --hex --example mixed > packet.hex
text2pcap -l 147 packet.hex packet.pcap

# 方式二：直接生成 PCAP
python sample_generator.py --pcap packet.pcap --example mixed
```

打开 `.pcap` 文件后，右键点击报文 → **Decode As** → 选择 `AUTOSAR BusMirror`。

## 协议结构

```
┌────────────────────────────────────────────────────────────────┐
│ Header（14字节）                                                │
├──────┬──────┬───────────────────┬───────────────┬──────────────┤
│ Ver  │ Seq  │ Timestamp (10字节)│ DataLength    │              │
│ uint8│ uint8│ 48位秒 + 32位纳秒  │ uint16 大端   │              │
└──────┴──────┴───────────────────┴───────────────┴──────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────┐
│ Data Item（变长，重复填充 DataLength 字节）                      │
├──────────┬───────┬───────────┬──────────────┬──────────────────┤
│ RelTs    │ Flags │ NetworkID │ [NetState]   │ [FrameID]        │
│ uint16 BE│ uint8 │ uint8     │ uint8        │ 变长 (1/3/4 字节) │
├──────────┴───────┴───────────┴──────────────┴──────────────────┤
│ [PayloadLen]     │ [Payload]                                   │
│ 变长 (1/2 字节)   │ N 字节                                      │
└──────────────────┴─────────────────────────────────────────────┘
```

### Flags 字节位定义

```
Bit 7  : NetworkStateAvailable  (1=网络状态字段存在)
Bit 6  : FrameIDAvailable       (1=FrameID 字段存在)
Bit 5  : PayloadAvailable       (1=负载长度+负载字段存在)
Bit 4-0: NetworkType            (0=Invalid, 1=CAN, 2=LIN, 3=FlexRay, 4=Ethernet,
                                  5-15=AUTOSAR保留, 16-31=客户自定义)
```

### 支持的网络类型

| 类型 | FrameID 大小 | PayloadLen 大小 | 解析程度 |
|------|-------------|-----------------|---------|
| CAN (1) | 4 字节 | 1 字节 (uint8) | 完整 — IDE、FDF、11/29位ID、NetworkState |
| LIN (2) | 1 字节 | 1 字节 (uint8) | 完整 — PID、校验位、无条件ID、NetworkState |
| FlexRay (3) | 3 字节 | 2 字节 (uint16) | 完整 — Channel A/B、Slot ID、Cycle、NetworkState |
| Ethernet (4) | 4 字节 | 2 字节 (uint16) | Controller/Port ID + VLAN ID（12位） |
| 自定义 (16–31) | 4 字节（默认） | 1 字节 | 原始数据显示 |

### CAN FrameID 结构（4字节）

```
Byte 0: [IDE|FDF|Reserved(0)|CAN_ID[28:24]]
Byte 1: CAN_ID[23:16]
Byte 2: CAN_ID[15:8]
Byte 3: CAN_ID[7:0]

IDE: 1=扩展29位ID, 0=标准11位ID
FDF: 1=CAN FD, 0=CAN 2.0
```

### FlexRay FrameID 结构（3字节）

```
Byte 0: [ChB|ChA|Reserved(00)|SlotValid|SlotID[10:8]]
Byte 1: SlotID[7:0]
Byte 2: Cycle Number
```

## 已知限制

- 仅支持串行化协议（`MirroringProtocolEnum=version1`），即目标总线为 FlexRay/Ethernet/CDD 的场景。CAN 2.0 目标总线的 ID 映射模式（`MirroringProtocolEnum=none`）暂不支持。
- Ethernet FrameID 布局（4字节：Controller ID + VLAN ID）基于 AUTOSAR 规范的合理推断，可能与具体实现有差异。
- 不做源帧的分片/重组处理。

## 文档

- [English version](README.md)

## 规范参考

- **AUTOSAR CP SWS BusMirroring** — [R23-11](https://www.autosar.org/fileadmin/standards/R23-11/CP/AUTOSAR_CP_SWS_BusMirroring.pdf) / [R24-11](https://www.autosar.org/fileadmin/standards/R24-11/CP/AUTOSAR_CP_SWS_BusMirroring.pdf)
- **AUTOSAR CP TPS SystemTemplate** — [R24-11](https://www.autosar.org/fileadmin/standards/R24-11/CP/AUTOSAR_CP_TPS_SystemTemplate.pdf)（BusMirror 相关章节）

## 环境要求

- **Wireshark** ≥ 3.0（Lua 5.2+）
- **Python** ≥ 3.7（仅生成器需要）
- **scapy**（可选，用于生成 PCAP：`pip install scapy`）

## 许可证

MIT
