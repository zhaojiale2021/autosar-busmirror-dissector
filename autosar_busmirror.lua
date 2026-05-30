-- ============================================================================
-- AUTOSAR BusMirror Protocol Wireshark Dissector
-- ============================================================================
-- Based on AUTOSAR CP SWS BusMirroring (R23-11 / R24-11)
-- Protocol version: 1 (serialization protocol for FlexRay / IP / CDD destinations)
--
-- Usage:
--   1. Place this file in Wireshark's Lua plugins directory, or
--   2. Load via Wireshark: Analyze → Lua → Evaluate, or
--   3. Start Wireshark with: wireshark -X lua_script:autosar_busmirror.lua
--
-- Protocol layout:
--   Header (14 bytes):
--     ProtocolVersion   uint8   (1 byte)
--     SequenceNumber    uint8   (1 byte)
--     TimestampSeconds  uint48  (6 bytes, network byte order / MSB first)
--     TimestampNanos    uint32  (4 bytes, network byte order / MSB first)
--     DataLength        uint16  (2 bytes, network byte order / MSB first)
--
--   Data Item (variable length, repeated DataLength bytes total):
--     RelativeTimestamp uint16  (2 bytes, 10us units, network byte order)
--     Flags             uint8   (1 byte)
--       [7]   NetworkStateAvailable
--       [6]   FrameIDAvailable
--       [5]   PayloadAvailable
--       [4:0] NetworkType (0=Invalid, 1=CAN, 2=LIN, 3=FlexRay, 4=Ethernet,
--                           5..15=AUTOSAR reserved, 16..31=customer-specific)
--     NetworkID         uint8   (1 byte)
--     [NetworkState]    uint8   (optional, bus-specific state flags)
--     [FrameID]         var     (optional, CAN=4, LIN=1, FlexRay=3, Ethernet=4 bytes)
--     [PayloadLength]   uint8   (optional, 1 byte for all network types per [SWS_Mirror_00110])
--     [Payload]         bytes   (optional, PayloadLength bytes)
--
-- FrameIDCAN (4 bytes):
--   Byte0[7]    IDE (1=Extended 29-bit, 0=Standard 11-bit)
--   Byte0[6]    FDF (1=CAN FD, 0=CAN 2.0)
--   Byte0[5]    Reserved (=0)
--   Byte0[4:0]  CAN_ID[28:24]
--   Byte1       CAN_ID[23:16]
--   Byte2       CAN_ID[15:8]
--   Byte3       CAN_ID[7:0]
--
-- FrameIDLIN (1 byte): Full LIN PID (2 parity bits + 6-bit unconditional ID)
--
-- FrameIDFlexRay (3 bytes):
--   Byte0[7]    Channel B available
--   Byte0[6]    Channel A available
--   Byte0[5:4]  Reserved (=00)
--   Byte0[3]    Slot Valid
--   Byte0[2:0]  Slot ID[10:8]
--   Byte1       Slot ID[7:0]
--   Byte2       Cycle Number
--
-- FrameIDEth (4 bytes):
--   Byte0-1     Controller/Port ID (uint16, MSB first)
--   Byte2-3     VLAN ID (uint16, lower 12 bits used, MSB first)
-- ============================================================================

local busmirror = Proto("busmirror", "AUTOSAR BusMirror")

-- ============================================================================
-- Protocol Constants
-- ============================================================================

local PROTOCOL_VERSION = 1

local NETWORK_TYPE = {
	[0] = "Invalid",
	[1] = "CAN",
	[2] = "LIN",
	[3] = "FlexRay",
	[4] = "Ethernet",
}

local CAN_FRAME_TYPE = {
	[0] = "CAN 2.0 Standard (11-bit ID)",
	[1] = "CAN 2.0 Standard (11-bit ID)",
	[2] = "CAN FD Standard (11-bit ID)",
	[3] = "CAN FD Standard (11-bit ID)",
	[4] = "CAN 2.0 Extended (29-bit ID)",
	[5] = "CAN 2.0 Extended (29-bit ID)",
	[6] = "CAN FD Extended (29-bit ID)",
	[7] = "CAN FD Extended (29-bit ID)",
}

local FR_CHANNEL = {
	[0] = "None",
	[1] = "Channel A",
	[2] = "Channel B",
	[3] = "Channels A+B",
}

-- ============================================================================
-- Protocol Fields
-- ============================================================================

-- Header fields
local f_proto_version   = ProtoField.uint8 ("busmirror.header.version",      "Protocol Version",        base.DEC)
local f_sequence_num    = ProtoField.uint8 ("busmirror.header.seqnum",        "Sequence Number",         base.DEC)
local f_ts_seconds      = ProtoField.bytes ("busmirror.header.ts_seconds",    "Timestamp Seconds (48-bit)", base.NONE)
local f_ts_nanos        = ProtoField.uint32("busmirror.header.ts_nanos",      "Timestamp Nanoseconds",   base.DEC)
local f_data_length     = ProtoField.uint16("busmirror.header.datalen",       "Data Length",             base.DEC)

-- Data item common fields
local f_rel_timestamp   = ProtoField.uint16("busmirror.item.rel_ts",          "Relative Timestamp (10us)", base.DEC)
local f_flags_netstate  = ProtoField.uint8 ("busmirror.item.flags.netstate",  "NetworkState Available", base.DEC, nil, 0x80)
local f_flags_frameid   = ProtoField.uint8 ("busmirror.item.flags.frameid",   "FrameID Available",      base.DEC, nil, 0x40)
local f_flags_payload   = ProtoField.uint8 ("busmirror.item.flags.payload",   "Payload Available",      base.DEC, nil, 0x20)
local f_network_type    = ProtoField.uint8 ("busmirror.item.nettype",         "Network Type",           base.DEC, NETWORK_TYPE, 0x1F)
local f_network_id      = ProtoField.uint8 ("busmirror.item.netid",           "Network ID",             base.DEC)

-- NetworkState fields (CAN)
local f_can_frames_lost   = ProtoField.uint8("busmirror.state.can.frames_lost",  "Frames Lost",         base.DEC, nil, 0x80)
local f_can_bus_online    = ProtoField.uint8("busmirror.state.can.bus_online",   "Bus Online",          base.DEC, nil, 0x40)
local f_can_error_passive = ProtoField.uint8("busmirror.state.can.err_passive",  "Error-Passive",       base.DEC, nil, 0x20)
local f_can_bus_off       = ProtoField.uint8("busmirror.state.can.bus_off",      "Bus-Off",             base.DEC, nil, 0x10)
local f_can_tx_err_cnt    = ProtoField.uint8("busmirror.state.can.tx_err_cnt",   "Tx Error Counter / 8",base.DEC, nil, 0x0F)

-- NetworkState fields (LIN)
local f_lin_frames_lost = ProtoField.uint8("busmirror.state.lin.frames_lost", "Frames Lost",       base.DEC, nil, 0x80)
local f_lin_bus_online  = ProtoField.uint8("busmirror.state.lin.bus_online",  "Bus Online",        base.DEC, nil, 0x40)
local f_lin_hdr_tx_err  = ProtoField.uint8("busmirror.state.lin.hdr_tx_err",  "Header Tx Error",   base.DEC, nil, 0x08)
local f_lin_tx_error    = ProtoField.uint8("busmirror.state.lin.tx_error",    "Tx Error",          base.DEC, nil, 0x04)
local f_lin_rx_error    = ProtoField.uint8("busmirror.state.lin.rx_error",    "Rx Error",          base.DEC, nil, 0x02)
local f_lin_rx_no_resp  = ProtoField.uint8("busmirror.state.lin.rx_no_resp",  "Rx No Response",    base.DEC, nil, 0x01)

-- NetworkState fields (FlexRay)
local f_fr_frames_lost   = ProtoField.uint8("busmirror.state.fr.frames_lost",   "Frames Lost",        base.DEC, nil, 0x80)
local f_fr_bus_online    = ProtoField.uint8("busmirror.state.fr.bus_online",    "Bus Online",         base.DEC, nil, 0x40)
local f_fr_bus_sync      = ProtoField.uint8("busmirror.state.fr.bus_sync",      "Bus Synchronous",    base.DEC, nil, 0x20)
local f_fr_normal_active = ProtoField.uint8("busmirror.state.fr.normal_active", "Normal Active",      base.DEC, nil, 0x10)
local f_fr_syntax_err    = ProtoField.uint8("busmirror.state.fr.syntax_err",    "Syntax Error",       base.DEC, nil, 0x08)
local f_fr_content_err   = ProtoField.uint8("busmirror.state.fr.content_err",   "Content Error",      base.DEC, nil, 0x04)
local f_fr_boundary_viol = ProtoField.uint8("busmirror.state.fr.boundary_viol", "Boundary Violation", base.DEC, nil, 0x02)
local f_fr_tx_conflict   = ProtoField.uint8("busmirror.state.fr.tx_conflict",   "Tx Conflict",        base.DEC, nil, 0x01)

-- FrameID fields (CAN)
local f_can_ide         = ProtoField.uint8 ("busmirror.fid.can.ide",          "IDE (1=Extended, 0=Standard)", base.DEC, nil, 0x80)
local f_can_fdf         = ProtoField.uint8 ("busmirror.fid.can.fdf",          "FDF (1=CAN FD, 0=CAN 2.0)",   base.DEC, nil, 0x40)
local f_can_id_upper    = ProtoField.uint8 ("busmirror.fid.can.id_upper",     "CAN ID bits [28:24]",         base.HEX, nil, 0x1F)
local f_can_id          = ProtoField.uint32("busmirror.fid.can.can_id",       "CAN Identifier",              base.HEX)
local f_can_frame_type  = ProtoField.string("busmirror.fid.can.frame_type",   "Frame Type")

-- FrameID fields (LIN)
local f_lin_pid           = ProtoField.uint8("busmirror.fid.lin.pid",         "LIN PID (Protected ID)",  base.HEX)
local f_lin_parity        = ProtoField.uint8("busmirror.fid.lin.parity",      "PID Parity bits [7:6]",   base.HEX, nil, 0xC0)
local f_lin_unconditional = ProtoField.uint8("busmirror.fid.lin.uncond_id",   "Unconditional ID [5:0]",  base.HEX, nil, 0x3F)

-- FrameID fields (FlexRay)
local f_fr_ch_b          = ProtoField.uint8 ("busmirror.fid.fr.ch_b",         "Channel B Available", base.DEC, nil, 0x80)
local f_fr_ch_a          = ProtoField.uint8 ("busmirror.fid.fr.ch_a",         "Channel A Available", base.DEC, nil, 0x40)
local f_fr_slot_valid    = ProtoField.uint8 ("busmirror.fid.fr.slot_valid",   "Slot Valid",          base.DEC, nil, 0x08)
local f_fr_slot_id_upper = ProtoField.uint8 ("busmirror.fid.fr.slot_upper",   "Slot ID [10:8]",      base.DEC, nil, 0x07)
local f_fr_slot_id_lower = ProtoField.uint8 ("busmirror.fid.fr.slot_lower",   "Slot ID [7:0]",       base.DEC)
local f_fr_slot_id       = ProtoField.uint16("busmirror.fid.fr.slot_id",      "Slot ID",             base.DEC)
local f_fr_cycle         = ProtoField.uint8 ("busmirror.fid.fr.cycle",        "Cycle Number",        base.DEC)
local f_fr_channel       = ProtoField.string("busmirror.fid.fr.channel",      "Channel")

-- FrameID fields (Ethernet)
local f_eth_ctrl_id = ProtoField.uint16("busmirror.fid.eth.ctrl_id", "Controller / Port ID",  base.DEC)
local f_eth_vlan_id = ProtoField.uint16("busmirror.fid.eth.vlan_id", "VLAN ID (12-bit)",      base.DEC)

-- Payload fields
local f_can_payload_len = ProtoField.uint8 ("busmirror.payload.can.len", "Payload Length", base.DEC)
local f_lin_payload_len = ProtoField.uint8 ("busmirror.payload.lin.len", "Payload Length", base.DEC)
local f_fr_payload_len  = ProtoField.uint8("busmirror.payload.fr.len",  "Payload Length", base.DEC)
local f_eth_payload_len = ProtoField.uint8("busmirror.payload.eth.len", "Payload Length", base.DEC)
local f_payload_data    = ProtoField.bytes ("busmirror.payload.data",    "Payload Data",   base.NONE)

-- Aggregate/raw fields
local f_net_state_raw   = ProtoField.uint8("busmirror.state.raw",  "Network State", base.HEX)
local f_frame_id_raw    = ProtoField.bytes("busmirror.fid.raw",    "Frame ID",      base.NONE)

-- ============================================================================
-- Register all fields
-- ============================================================================

busmirror.fields = {
	-- Header
	f_proto_version, f_sequence_num, f_ts_seconds, f_ts_nanos,
	f_data_length,
	-- Data item common
	f_rel_timestamp, f_flags_netstate, f_flags_frameid, f_flags_payload,
	f_network_type, f_network_id,
	-- CAN NetworkState
	f_can_frames_lost, f_can_bus_online, f_can_error_passive, f_can_bus_off, f_can_tx_err_cnt,
	-- LIN NetworkState
	f_lin_frames_lost, f_lin_bus_online, f_lin_hdr_tx_err, f_lin_tx_error, f_lin_rx_error, f_lin_rx_no_resp,
	-- FlexRay NetworkState
	f_fr_frames_lost, f_fr_bus_online, f_fr_bus_sync, f_fr_normal_active,
	f_fr_syntax_err, f_fr_content_err, f_fr_boundary_viol, f_fr_tx_conflict,
	-- CAN FrameID
	f_can_ide, f_can_fdf, f_can_id_upper, f_can_id, f_can_frame_type,
	-- LIN FrameID
	f_lin_pid, f_lin_parity, f_lin_unconditional,
	-- FlexRay FrameID
	f_fr_ch_b, f_fr_ch_a, f_fr_slot_valid, f_fr_slot_id_upper, f_fr_slot_id_lower,
	f_fr_slot_id, f_fr_cycle, f_fr_channel,
	-- Ethernet FrameID
	f_eth_ctrl_id, f_eth_vlan_id,
	-- Payload
	f_can_payload_len, f_lin_payload_len, f_fr_payload_len, f_eth_payload_len, f_payload_data,
	-- Raw
	f_net_state_raw, f_frame_id_raw,
}

-- ============================================================================
-- Helper Functions
-- ============================================================================

local function get_network_type_name(nt)
	return NETWORK_TYPE[nt] or string.format("Reserved/Custom (%d)", nt)
end

local function get_can_frame_type_name(ide, fdf)
	local t = 0
	if ide == 1 then t = t + 4 end
	if fdf == 1 then t = t + 2 end
	return CAN_FRAME_TYPE[t] or string.format("Unknown", t)
end

local function get_fr_channel_name(ch_a, ch_b)
	local v = 0
	if ch_a == 1 then v = v + 1 end
	if ch_b == 1 then v = v + 2 end
	return FR_CHANNEL[v] or "Unknown"
end

-- Format timestamp from 6-byte seconds + 4-byte nanoseconds
-- sec_bytes: TvbRange of 6 bytes (48-bit, MSB first)
-- nanos: uint32
local function format_timestamp(sec_bytes, nanos)
	-- Split 48-bit seconds: upper 16 bits + lower 32 bits
	local hi16 = sec_bytes:range(0, 2):uint()  -- bits 47..32
	local lo32 = sec_bytes:range(2, 4):uint()  -- bits 31..0
	-- Lua numbers are double-precision floats (53-bit integer precision),
	-- so hi16 * 2^32 + lo32 fits exactly for 48-bit seconds.
	local secs = hi16 * 0x100000000 + lo32
	-- Build nanosecond string manually to avoid Lua 5.3 float/int issues with %d/%u
	local ns_str = tostring(nanos)
	if #ns_str > 9 then ns_str = ns_str:sub(1, 9)
	elseif #ns_str < 9 then ns_str = string.rep("0", 9 - #ns_str) .. ns_str end
	-- os.date may throw on some platforms (e.g. Windows) for timestamps beyond
	-- the platform time_t range (year 2038 on 32-bit, or distant-future 48-bit values).
	-- Use pcall to catch the error and fall back to epoch display.
	local success, ds = pcall(os.date, "!%Y-%m-%d %H:%M:%S", secs)
	if success and ds then
		return ds .. "." .. ns_str
	else
		return string.format("%.0f", secs) .. "." .. ns_str .. " (epoch)"
	end
end

-- Read a 2-byte big-endian value
local function read_uint16_be(tvb, off)
	return tvb(off, 2):uint()
end

-- ============================================================================
-- Dissector Functions
-- ============================================================================

-- Dissect the 14-byte header.
-- buffer: full packet buffer (Tvb)
-- pinfo: packet info
-- tree: root tree item for the header
-- Returns: datalen (number of bytes in data items following the header)
local function dissect_header(buffer, pinfo, tree)
	local off = 0

	-- Protocol Version (1 byte)
	local ver = buffer(off, 1):uint()
	if ver == PROTOCOL_VERSION then
		tree:add(f_proto_version, buffer(off, 1)):set_text("Protocol Version: " .. ver .. " (Current)")
	else
		tree:add(f_proto_version, buffer(off, 1)):set_text("Protocol Version: " .. ver .. " (Unknown)")
	end
	pinfo.cols.info:prepend("BusMirror v" .. ver .. " ")
	off = off + 1

	-- Sequence Number (1 byte)
	local seq = buffer(off, 1):uint()
	tree:add(f_sequence_num, buffer(off, 1))
	pinfo.cols.info:append("Seq=" .. seq .. " ")
	off = off + 1

	-- Timestamp Seconds (6 bytes, MSB first)
	local ts_sec_tvb = buffer(off, 6)
	tree:add(f_ts_seconds, ts_sec_tvb)
	off = off + 6

	-- Timestamp Nanoseconds (4 bytes, MSB first)
	local ts_nanos = buffer(off, 4):uint()
	tree:add(f_ts_nanos, buffer(off, 4))
	off = off + 4

	-- Absolute Timestamp (informational)
		local ts_str = format_timestamp(ts_sec_tvb, ts_nanos)
		tree:add(buffer(0, 14), "Epoch Timestamp: " .. ts_str)

	-- Data Length (2 bytes, MSB first)
	local datalen = read_uint16_be(buffer, off)
	tree:add(f_data_length, buffer(off, 2))
	off = off + 2

	pinfo.cols.info:append("Items=" .. datalen .. "B")

	return datalen
end

-- Dissect NetworkState (1 byte) based on network type.
-- Returns the new offset (offset + 1).
local function dissect_network_state(tvb, offset, net_type, tree)
	local raw = tvb(offset, 1):uint()
	local state_tree = tree:add(f_net_state_raw, tvb(offset, 1))

	if net_type == 1 then -- CAN
		state_tree:set_text("Network State (CAN): 0x" .. string.format("%02X", raw))
		state_tree:add(f_can_frames_lost,   tvb(offset, 1))
		state_tree:add(f_can_bus_online,    tvb(offset, 1))
		state_tree:add(f_can_error_passive, tvb(offset, 1))
		state_tree:add(f_can_bus_off,       tvb(offset, 1))
		state_tree:add(f_can_tx_err_cnt,    tvb(offset, 1))
	elseif net_type == 2 then -- LIN
		state_tree:set_text("Network State (LIN): 0x" .. string.format("%02X", raw))
		state_tree:add(f_lin_frames_lost, tvb(offset, 1))
		state_tree:add(f_lin_bus_online,  tvb(offset, 1))
		state_tree:add(f_lin_hdr_tx_err,  tvb(offset, 1))
		state_tree:add(f_lin_tx_error,    tvb(offset, 1))
		state_tree:add(f_lin_rx_error,    tvb(offset, 1))
		state_tree:add(f_lin_rx_no_resp,  tvb(offset, 1))
	elseif net_type == 3 then -- FlexRay
		state_tree:set_text("Network State (FlexRay): 0x" .. string.format("%02X", raw))
		state_tree:add(f_fr_frames_lost,   tvb(offset, 1))
		state_tree:add(f_fr_bus_online,    tvb(offset, 1))
		state_tree:add(f_fr_bus_sync,      tvb(offset, 1))
		state_tree:add(f_fr_normal_active, tvb(offset, 1))
		state_tree:add(f_fr_syntax_err,    tvb(offset, 1))
		state_tree:add(f_fr_content_err,   tvb(offset, 1))
		state_tree:add(f_fr_boundary_viol, tvb(offset, 1))
		state_tree:add(f_fr_tx_conflict,   tvb(offset, 1))
	else
		state_tree:set_text("Network State (" .. get_network_type_name(net_type) .. "): 0x" .. string.format("%02X", raw))
	end

	return offset + 1
end

-- Dissect FrameID based on network type.
-- Returns the new offset after the FrameID.
local function dissect_frame_id(tvb, offset, net_type, tree, pinfo)
	if net_type == 1 then -- CAN (4 bytes)
		local fid_tree = tree:add(f_frame_id_raw, tvb(offset, 4))
		fid_tree:set_text("Frame ID (CAN)")

		local byte0 = tvb(offset, 1):uint()
		local ide = bit.band(bit.rshift(byte0, 7), 1)
		local fdf = bit.band(bit.rshift(byte0, 6), 1)
		local id_upper = bit.band(byte0, 0x1F)

		fid_tree:add(f_can_ide, tvb(offset, 1))
		fid_tree:add(f_can_fdf, tvb(offset, 1))
		fid_tree:add(f_can_id_upper, tvb(offset, 1))

		-- Always extract the full 29-bit CAN ID from all 4 bytes
		local can_id_29bit = bit.bor(
			bit.lshift(id_upper, 24),
			bit.lshift(tvb(offset + 1, 1):uint(), 16),
			bit.lshift(tvb(offset + 2, 1):uint(), 8),
			tvb(offset + 3, 1):uint()
		)

		local frame_type_str = get_can_frame_type_name(ide, fdf)

		if ide == 1 then
			-- Extended 29-bit ID
			fid_tree:add(f_can_id, tvb(offset, 4))
				:set_text(string.format("CAN ID: 0x%08X (Extended 29-bit)", can_id_29bit))
			pinfo.cols.info:append(string.format("[CAN Ext 0x%08X] ", can_id_29bit))
		else
			-- Standard 11-bit ID: only lower 11 bits are used
			local can_id_11bit = bit.band(can_id_29bit, 0x7FF)
			fid_tree:add(f_can_id, tvb(offset, 4))
				:set_text(string.format("CAN ID: 0x%03X (Standard 11-bit)", can_id_11bit))
			pinfo.cols.info:append(string.format("[CAN Std 0x%03X] ", can_id_11bit))
		end

		fid_tree:add(f_can_frame_type, frame_type_str)

		return offset + 4

	elseif net_type == 2 then -- LIN (1 byte)
		local fid_tree = tree:add(f_frame_id_raw, tvb(offset, 1))
		fid_tree:set_text("Frame ID (LIN)")

		local pid = tvb(offset, 1):uint()
		local uncond_id = bit.band(pid, 0x3F)
		fid_tree:add(f_lin_pid, tvb(offset, 1))
		fid_tree:add(f_lin_parity, tvb(offset, 1))
		fid_tree:add(f_lin_unconditional, tvb(offset, 1))
			:set_text(string.format("Unconditional ID [5:0]: 0x%02X", uncond_id))

		pinfo.cols.info:append(string.format("[LIN PID=0x%02X ID=0x%02X] ", pid, uncond_id))

		return offset + 1

	elseif net_type == 3 then -- FlexRay (3 bytes)
		local fid_tree = tree:add(f_frame_id_raw, tvb(offset, 3))
		fid_tree:set_text("Frame ID (FlexRay)")

		local byte0 = tvb(offset, 1):uint()
		local ch_b = bit.band(bit.rshift(byte0, 7), 1)
		local ch_a = bit.band(bit.rshift(byte0, 6), 1)
		local slot_valid = bit.band(bit.rshift(byte0, 3), 1)
		local slot_upper = bit.band(byte0, 0x07)

		fid_tree:add(f_fr_ch_b, tvb(offset, 1))
		fid_tree:add(f_fr_ch_a, tvb(offset, 1))
		fid_tree:add(f_fr_slot_valid, tvb(offset, 1))
		fid_tree:add(f_fr_slot_id_upper, tvb(offset, 1))
		fid_tree:add(f_fr_slot_id_lower, tvb(offset + 1, 1))
		fid_tree:add(f_fr_cycle, tvb(offset + 2, 1))

		local slot_id = bit.bor(bit.lshift(slot_upper, 8), tvb(offset + 1, 1):uint())
		local cycle = tvb(offset + 2, 1):uint()
		local channel_str = get_fr_channel_name(ch_a, ch_b)

		fid_tree:add(f_fr_slot_id, slot_id):set_text("Slot ID: " .. slot_id)
		fid_tree:add(f_fr_channel, channel_str)

		pinfo.cols.info:append(string.format("[FlexRay Slot=%d Cyc=%d %s] ", slot_id, cycle, channel_str))

		return offset + 3

	elseif net_type == 4 then -- Ethernet (4 bytes)
		local fid_tree = tree:add(f_frame_id_raw, tvb(offset, 4))
		fid_tree:set_text("Frame ID (Ethernet)")

		local ctrl_id = read_uint16_be(tvb, offset)
		local vlan_raw = read_uint16_be(tvb, offset + 2)
		local vlan_id = bit.band(vlan_raw, 0x0FFF)

		fid_tree:add(f_eth_ctrl_id, tvb(offset, 2))
		fid_tree:add(f_eth_vlan_id, tvb(offset + 2, 2))
			:set_text(string.format("VLAN ID (12-bit): %d (0x%03X)", vlan_id, vlan_id))

		pinfo.cols.info:append(string.format("[Eth Ctrl=%d VLAN=%d] ", ctrl_id, vlan_id))

		return offset + 4

	else
		-- Unknown network type; conservatively skip 4 bytes
		local fid_tree = tree:add(f_frame_id_raw, tvb(offset, 4))
		fid_tree:set_text(string.format("Frame ID (Unknown NetType=%d)", net_type))

		return offset + 4
	end
end

-- Dissect Payload based on network type.
-- Returns the new offset after the payload.
local function dissect_payload(tvb, offset, net_type, tree, pinfo)
	-- Per [SWS_Mirror_00110]: PayloadLength width is 8 bits (1 byte) for all network types.
	local payload_len

	if net_type == 1 then -- CAN: 1-byte length
		payload_len = tvb(offset, 1):uint()
		tree:add(f_can_payload_len, tvb(offset, 1))
	elseif net_type == 2 then -- LIN: 1-byte length
		payload_len = tvb(offset, 1):uint()
		tree:add(f_lin_payload_len, tvb(offset, 1))
	elseif net_type == 3 then -- FlexRay: 1-byte length (spec: 8 bits)
		payload_len = tvb(offset, 1):uint()
		tree:add(f_fr_payload_len, tvb(offset, 1))
	elseif net_type == 4 then -- Ethernet: 1-byte length (spec: 8 bits)
		payload_len = tvb(offset, 1):uint()
		tree:add(f_eth_payload_len, tvb(offset, 1))
	else
		-- Unknown type: use 1-byte length
		payload_len = tvb(offset, 1):uint()
	end
	offset = offset + 1

	if payload_len > 0 then
		tree:add(f_payload_data, tvb(offset, payload_len))
		pinfo.cols.info:append(string.format("Pl=%dB ", payload_len))
	end

	return offset + payload_len
end

-- Dissect a single data item.
-- Returns the new offset after consuming this item.
local function dissect_data_item(tvb, offset, tree, pinfo)
	-- Relative Timestamp (2 bytes, MSB first, units of 10 µs)
	local rel_ts = read_uint16_be(tvb, offset)
	local rel_us = rel_ts * 10
	local rel_ms = rel_us / 1000.0
	tree:add(f_rel_timestamp, tvb(offset, 2))
		:set_text(string.format("Relative Timestamp: %d (%.3f ms / %d µs)", rel_ts, rel_ms, rel_us))
	offset = offset + 2

	-- Flags byte
	local flags = tvb(offset, 1):uint()
	local netstate_avail = bit.band(bit.rshift(flags, 7), 1)
	local frameid_avail  = bit.band(bit.rshift(flags, 6), 1)
	local payload_avail  = bit.band(bit.rshift(flags, 5), 1)
	local net_type       = bit.band(flags, 0x1F)

	local flags_tree = tree:add(tvb(offset, 1), "Flags (0x" .. string.format("%02X", flags) .. ")")
	flags_tree:add(f_flags_netstate, tvb(offset, 1))
	flags_tree:add(f_flags_frameid, tvb(offset, 1))
	flags_tree:add(f_flags_payload, tvb(offset, 1))
	flags_tree:add(f_network_type, tvb(offset, 1))
	offset = offset + 1

	-- Network ID (1 byte)
	local net_id = tvb(offset, 1):uint()
	tree:add(f_network_id, tvb(offset, 1))
	offset = offset + 1

	local nt_name = get_network_type_name(net_type)
	pinfo.cols.info:append(string.format("| %s#%d ", nt_name, net_id))

	-- NetworkState (optional, 1 byte)
	if netstate_avail == 1 then
		offset = dissect_network_state(tvb, offset, net_type, tree)
	end

	-- FrameID (optional, variable length)
	if frameid_avail == 1 then
		offset = dissect_frame_id(tvb, offset, net_type, tree, pinfo)
	end

	-- Payload (optional, variable length)
	if payload_avail == 1 then
		offset = dissect_payload(tvb, offset, net_type, tree, pinfo)
	end

	return offset
end

-- ============================================================================
-- Main Dissector Function
-- ============================================================================

function busmirror.dissector(tvb, pinfo, tree)
	local buf_len = tvb:len()

	if buf_len < 14 then
		-- Frame too short; let another heuristic try if applicable
		return 0
	end

	pinfo.cols.protocol = "BusMirror"

	local main_tree = tree:add(busmirror, tvb(), "AUTOSAR BusMirror Protocol")

	-- ---- Header dissection ----
	local hdr_tree = main_tree:add(tvb(0, 14), "Header (14 bytes)")
	local data_length = dissect_header(tvb, pinfo, hdr_tree)

	if data_length == 0 then
		return buf_len
	end

	-- ---- Data Items dissection ----
	local items_start = 14
	local items_end   = items_start + data_length

	if items_end > buf_len then
		main_tree:add_expert_info(PI_MALFORMED, PI_WARN,
			string.format("Declared DataLength (%d) exceeds available buffer (%d bytes remaining)",
				data_length, buf_len - items_start))
		items_end = buf_len
	end

	local items_tvb = tvb(items_start, items_end - items_start)
	local items_tree = main_tree:add(items_tvb, "Data Items (" .. data_length .. " bytes declared)")

	local item_idx = 0
	local pos = items_start

	while pos < items_end do
		item_idx = item_idx + 1
		local item_tvb = tvb(pos, items_end - pos)
		local item_tree = items_tree:add(item_tvb, "Data Item #" .. item_idx)
		local prev_pos = pos

		pos = dissect_data_item(tvb, pos, item_tree, pinfo)

		-- Guard against parsers that don't advance
		if pos <= prev_pos then
			items_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Parser stalled on Data Item #" .. item_idx)
			break
		end
	end

	-- Report trailing bytes inside the declared data region that weren't consumed
	if pos < items_end then
		local remaining = items_end - pos
		items_tree:add_expert_info(PI_UNDECODED, PI_WARN,
			string.format("%d byte(s) left unparsed in declared data area", remaining))
	end

	return buf_len
end

-- ============================================================================
-- Protocol Registration
-- ============================================================================

-- Default port: configurable via Wireshark Preferences
busmirror.prefs.port = Pref.uint("TCP / UDP Port", 30490,
	"Destination port when BusMirror runs over Ethernet (TCP or UDP)")

local function reregister_ports()
	local port = busmirror.prefs.port
	DissectorTable.get("tcp.port"):add(port, busmirror)
	DissectorTable.get("udp.port"):add(port, busmirror)
end

reregister_ports()
busmirror.prefs_changed = reregister_ports

-- Heuristic dissector: detect BusMirror frames on any TCP/UDP payload by
-- checking the protocol version byte and DataLength sanity.
local function heuristic_dissect(tvb, pinfo, tree)
	if tvb:len() < 14 then
		return false
	end

	-- ProtocolVersion must be 1
	if tvb(0, 1):uint() ~= PROTOCOL_VERSION then
		return false
	end

	-- DataLength (at offset 12, 2 bytes) + 14 must not exceed buffer size
	local declared_len = read_uint16_be(tvb, 12)
	if declared_len + 14 > tvb:len() then
		return false
	end

	-- Sanity: nanoseconds < 1e9
	local nanos = tvb(8, 4):uint()
	if nanos >= 1000000000 then
		return false
	end

	busmirror.dissector(tvb, pinfo, tree)
	return true
end

busmirror:register_heuristic("udp", heuristic_dissect)
busmirror:register_heuristic("tcp", heuristic_dissect)

-- Metadata: description is set via Proto(name, desc) constructor above.
-- For Wireshark >= 4.0 the following can be uncommented:
-- busmirror.description = "AUTOSAR BusMirror Protocol (CP SWS BusMirroring R23-11/R24-11)"
-- busmirror.author      = "generated from AUTOSAR specification"
-- busmirror.version     = "1.0"
