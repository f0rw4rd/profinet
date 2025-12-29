"""Tests for PROFINET block parsing module."""

import pytest
import struct
from profinet import blocks, indices


class TestBlockHeader:
    """Tests for BlockHeader parsing."""

    def test_parse_block_header_valid(self):
        """Test parsing a valid 6-byte block header."""
        # BlockType=0x0400 (MultipleBlockHeader), Length=0x0090, Version=1.0
        data = struct.pack(">HHBB", 0x0400, 0x0090, 0x01, 0x00)
        header, offset = blocks.parse_block_header(data)

        assert header.block_type == 0x0400
        assert header.block_length == 0x0090
        assert header.version_high == 1
        assert header.version_low == 0
        assert header.body_length == 0x008E  # 0x0090 - 2
        assert offset == 6

    def test_parse_block_header_short_data(self):
        """Test error handling for truncated data."""
        data = b"\x04\x00\x00"  # Only 3 bytes
        with pytest.raises(ValueError, match="requires 6 bytes"):
            blocks.parse_block_header(data)

    def test_parse_block_header_with_offset(self):
        """Test parsing with non-zero offset."""
        prefix = b"\xFF\xFF\xFF\xFF"  # 4 bytes of padding
        header_data = struct.pack(">HHBB", 0x0240, 0x0024, 0x01, 0x00)
        data = prefix + header_data

        header, offset = blocks.parse_block_header(data, 4)

        assert header.block_type == 0x0240
        assert header.block_length == 0x0024
        assert offset == 10  # 4 + 6

    def test_block_header_type_name(self):
        """Test block type name lookup."""
        data = struct.pack(">HHBB", indices.BLOCK_MULTIPLE_HEADER, 0x0010, 1, 0)
        header, _ = blocks.parse_block_header(data)
        assert header.type_name == "MultipleBlockHeader"

        data = struct.pack(">HHBB", 0x9999, 0x0010, 1, 0)
        header, _ = blocks.parse_block_header(data)
        assert "Unknown" in header.type_name


class TestMultipleBlockHeader:
    """Tests for MultipleBlockHeader (0x0400) parsing."""

    def test_parse_multiple_block_header(self):
        """Test parsing MultipleBlockHeader body."""
        # 2 bytes padding + API(4) + Slot(2) + Subslot(2)
        data = struct.pack(">xxIHH", 0x00000000, 0x0000, 0x8000)
        api, slot, subslot, body_offset = blocks.parse_multiple_block_header(data)

        assert api == 0
        assert slot == 0
        assert subslot == 0x8000
        assert body_offset == 10  # 2 (padding) + 8 (api+slot+subslot)

    def test_parse_multiple_block_header_nonzero_api(self):
        """Test parsing with non-zero API."""
        data = struct.pack(">xxIHH", 0x00000001, 0x0002, 0x0001)
        api, slot, subslot, _ = blocks.parse_multiple_block_header(data)

        assert api == 1
        assert slot == 2
        assert subslot == 1

    def test_parse_multiple_block_header_truncated(self):
        """Test error on truncated data."""
        data = b"\x00\x00\x00\x00"  # Only 4 bytes
        with pytest.raises(ValueError, match="requires 8 bytes"):
            blocks.parse_multiple_block_header(data)


class TestPDInterfaceDataReal:
    """Tests for PDInterfaceDataReal (0x0240) parsing."""

    def test_parse_interface_data(self):
        """Test parsing PDInterfaceDataReal block body.

        Alignment is relative to block start (6-byte header + body).
        For a 10-byte chassis ID: header(6) + len(1) + chassis(10) = 17
        Align to 4 -> 20, so MAC starts at body offset 14 (3 bytes padding).
        """
        # Real device format: chassis_len=10, 3 bytes padding, MAC, 2 bytes padding, IP/Subnet/GW
        # Using chassis "AAAAAAAAAA" (10 bytes) to match real alignment
        data = bytes.fromhex(
            "0A"  # chassis_len = 10
            "41414141414141414141"  # "AAAAAAAAAA" (10 bytes)
            "000000"  # 3 bytes padding (block offset 17 -> 20)
            "001122334455"  # MAC (6 bytes, block offset 20-25)
            "0000"  # 2 bytes padding (block offset 26 -> 28)
            "C0A80164"  # IP: 192.168.1.100
            "FFFFFF00"  # Subnet: 255.255.255.0
            "C0A80101"  # Gateway: 192.168.1.1
        )

        info = blocks.parse_pd_interface_data_real(data)

        assert info.chassis_id == "AAAAAAAAAA"
        assert info.mac_address == b"\x00\x11\x22\x33\x44\x55"
        assert info.ip_str == "192.168.1.100"
        assert info.subnet_str == "255.255.255.0"
        assert info.gateway_str == "192.168.1.1"

    def test_interface_info_mac_str(self):
        """Test MAC address string formatting."""
        info = blocks.InterfaceInfo(
            chassis_id="test",
            mac_address=b"\xAB\xCD\xEF\x01\x23\x45",
            ip_address=b"\x00\x00\x00\x00",
            subnet_mask=b"\x00\x00\x00\x00",
            gateway=b"\x00\x00\x00\x00",
        )
        assert info.mac_str == "ab:cd:ef:01:23:45"


class TestPDPortDataReal:
    """Tests for PDPortDataReal (0x020F) parsing."""

    def test_parse_port_data_minimal(self):
        """Test parsing minimal port data."""
        # Slot(2) + Subslot(2) + PortIDLen(1) + PortID + NumPeers(1)
        port_id = b"port-001"
        data = struct.pack(">HH", 0, 0x8001) + bytes([len(port_id)]) + port_id + b"\x00"

        port = blocks.parse_pd_port_data_real(data, slot=0, subslot=0x8001)

        assert port.slot == 0
        assert port.subslot == 0x8001
        assert port.port_id == "port-001"
        assert len(port.peers) == 0

    def test_parse_port_data_with_peer(self):
        """Test parsing port data with peer information."""
        # Build test data with one peer
        port_id = b"port-001"
        peer_port = b"port-002"
        peer_chassis = b"peer-dev"
        peer_mac = b"\x00\x11\x22\x33\x44\x66"

        data = bytearray()
        # Slot/Subslot
        data.extend(struct.pack(">HH", 0, 0x8001))
        # Port ID
        data.append(len(port_id))
        data.extend(port_id)
        # Number of peers
        data.append(1)
        # Padding to 4-byte boundary
        while len(data) % 4:
            data.append(0)
        # Peer port ID
        data.append(len(peer_port))
        data.extend(peer_port)
        # Peer chassis ID
        data.append(len(peer_chassis))
        data.extend(peer_chassis)
        # Padding
        while len(data) % 4:
            data.append(0)
        # Peer MAC
        data.extend(peer_mac)
        # Padding
        while len(data) % 4:
            data.append(0)
        # MAU type
        data.extend(struct.pack(">H", 16))  # 100BaseTX
        # Padding
        while len(data) % 4:
            data.append(0)

        port = blocks.parse_pd_port_data_real(bytes(data))

        assert port.port_id == "port-001"
        assert len(port.peers) == 1
        assert port.peers[0].port_id == "port-002"
        assert port.peers[0].chassis_id == "peer-dev"


class TestSlotInfo:
    """Tests for SlotInfo data class."""

    def test_slot_info_repr(self):
        """Test SlotInfo string representation."""
        slot = blocks.SlotInfo(api=0, slot=1, subslot=0x8001)
        assert "api=0" in repr(slot)
        assert "slot=1" in repr(slot)
        assert "0x8001" in repr(slot)

    def test_slot_info_with_idents(self):
        """Test SlotInfo with module/submodule identifiers."""
        slot = blocks.SlotInfo(
            api=0,
            slot=0,
            subslot=1,
            module_ident=0x12345678,
            submodule_ident=0x00000001,
        )
        assert slot.module_ident == 0x12345678
        assert slot.submodule_ident == 0x00000001


class TestPDRealData:
    """Tests for PDRealData (0xF841) parsing."""

    def test_parse_empty_data(self):
        """Test parsing empty data returns empty result."""
        result = blocks.parse_pd_real_data(b"")
        assert len(result.slots) == 0
        assert result.interface is None
        assert len(result.ports) == 0

    def test_parse_single_multiple_block(self):
        """Test parsing PDRealData with single MultipleBlockHeader."""
        # Build a MultipleBlockHeader (0x0400) containing PDInterfaceDataReal (0x0240)
        # Outer block header
        outer_data = bytearray()

        # MultipleBlockHeader header: type=0x0400, length=TBD, version=1.0
        outer_data.extend(struct.pack(">HHBB", 0x0400, 0, 1, 0))
        # Padding (2 bytes) + API(4) + Slot(2) + Subslot(2)
        outer_data.extend(struct.pack(">xxIHH", 0, 0, 0x8000))

        # Nested PDInterfaceDataReal (0x0240)
        inner_data = bytearray()
        chassis = b"test"
        inner_data.append(len(chassis))
        inner_data.extend(chassis)
        # Padding
        while len(inner_data) % 4:
            inner_data.append(0)
        # MAC
        inner_data.extend(b"\x00\x11\x22\x33\x44\x55")
        # Padding
        while len(inner_data) % 4:
            inner_data.append(0)
        # IP/Subnet/GW
        inner_data.extend(b"\xC0\xA8\x01\x01")
        inner_data.extend(b"\xFF\xFF\xFF\x00")
        inner_data.extend(b"\xC0\xA8\x01\x01")

        # Inner block header
        inner_header = struct.pack(">HHBB", 0x0240, len(inner_data) + 2, 1, 0)

        # Combine
        outer_data.extend(inner_header)
        outer_data.extend(inner_data)

        # Update outer block length
        outer_length = len(outer_data) - 4  # Exclude type and length fields
        struct.pack_into(">H", outer_data, 2, outer_length)

        result = blocks.parse_pd_real_data(bytes(outer_data))

        assert len(result.slots) == 1
        assert result.slots[0].slot == 0
        assert result.slots[0].subslot == 0x8000
        assert result.interface is not None
        assert result.interface.chassis_id == "test"


class TestRealIdentificationData:
    """Tests for RealIdentificationData (0xF000/0x0013) parsing."""

    def test_parse_version_1_0(self):
        """Test parsing RealIdentificationData version 1.0."""
        # Block header: type=0x0013, length, version=1.0
        data = bytearray()
        data.extend(struct.pack(">HHBB", 0x0013, 0, 1, 0))

        # NumberOfSlots = 2
        data.extend(struct.pack(">H", 2))

        # Slot 0: SlotNumber(2) + ModuleIdent(4) + NumSubslots(2)
        data.extend(struct.pack(">HIH", 0, 0x00010001, 2))
        # Subslot 1
        data.extend(struct.pack(">HI", 1, 0x00000001))
        # Subslot 0x8000
        data.extend(struct.pack(">HI", 0x8000, 0x00000002))

        # Slot 1: SlotNumber(2) + ModuleIdent(4) + NumSubslots(2)
        data.extend(struct.pack(">HIH", 1, 0x00020002, 1))
        # Subslot 1
        data.extend(struct.pack(">HI", 1, 0x00000001))

        # Update length
        struct.pack_into(">H", data, 2, len(data) - 4)

        result = blocks.parse_real_identification_data(bytes(data))

        assert result.version == (1, 0)
        assert len(result.slots) == 3  # 2 + 1 subslots total
        assert result.slots[0].slot == 0
        assert result.slots[0].subslot == 1
        assert result.slots[1].slot == 0
        assert result.slots[1].subslot == 0x8000
        assert result.slots[2].slot == 1
        assert result.slots[2].subslot == 1

    def test_parse_version_1_1_with_api(self):
        """Test parsing RealIdentificationData version 1.1 with API."""
        # Block header: type=0x0013, length, version=1.1
        data = bytearray()
        data.extend(struct.pack(">HHBB", 0x0013, 0, 1, 1))

        # NumberOfAPIs = 1
        data.extend(struct.pack(">H", 1))

        # API = 0
        data.extend(struct.pack(">I", 0))

        # NumberOfSlots = 1
        data.extend(struct.pack(">H", 1))

        # Slot 0: SlotNumber(2) + ModuleIdent(4) + NumSubslots(2)
        data.extend(struct.pack(">HIH", 0, 0x12345678, 1))
        # Subslot 1
        data.extend(struct.pack(">HI", 1, 0x87654321))

        # Update length
        struct.pack_into(">H", data, 2, len(data) - 4)

        result = blocks.parse_real_identification_data(bytes(data))

        assert result.version == (1, 1)
        assert len(result.slots) == 1
        assert result.slots[0].api == 0
        assert result.slots[0].slot == 0
        assert result.slots[0].subslot == 1
        assert result.slots[0].module_ident == 0x12345678
        assert result.slots[0].submodule_ident == 0x87654321

    def test_parse_empty_returns_empty(self):
        """Test parsing empty data returns empty result."""
        result = blocks.parse_real_identification_data(b"")
        assert len(result.slots) == 0


class TestPortStatistics:
    """Tests for PDPortStatistic (0x0251) parsing."""

    def test_parse_port_statistics(self):
        """Test parsing port statistics block."""
        # CounterStatus(2) + 6x uint32
        data = struct.pack(
            ">HIIIIII",
            0x0001,  # counter_status
            1000,  # ifInOctets
            2000,  # ifOutOctets
            5,  # ifInDiscards
            3,  # ifOutDiscards
            1,  # ifInErrors
            2,  # ifOutErrors
        )

        result = blocks.parse_port_statistics(data)

        assert result["counter_status"] == 1
        assert result["in_octets"] == 1000
        assert result["out_octets"] == 2000
        assert result["in_discards"] == 5
        assert result["out_discards"] == 3
        assert result["in_errors"] == 1
        assert result["out_errors"] == 2

    def test_parse_port_statistics_truncated(self):
        """Test parsing truncated data returns empty dict."""
        data = b"\x00\x01"  # Only 2 bytes
        result = blocks.parse_port_statistics(data)
        assert result == {}


class TestBlockTypeConstants:
    """Tests for block type constants in indices module."""

    def test_block_type_constants_defined(self):
        """Test that all expected block type constants are defined."""
        assert indices.BLOCK_MULTIPLE_HEADER == 0x0400
        assert indices.BLOCK_PD_PORT_DATA_REAL == 0x020F
        assert indices.BLOCK_PD_INTERFACE_DATA_REAL == 0x0240
        assert indices.BLOCK_PD_REAL_DATA == 0xF841
        assert indices.BLOCK_REAL_IDENTIFICATION_DATA == 0x0013
        assert indices.BLOCK_REAL_IDENTIFICATION_DATA_API == 0xF000

    def test_get_block_type_name(self):
        """Test block type name lookup function."""
        assert indices.get_block_type_name(0x0400) == "MultipleBlockHeader"
        assert indices.get_block_type_name(0x020F) == "PDPortDataReal"
        assert indices.get_block_type_name(0x0240) == "PDInterfaceDataReal"
        assert "Unknown" in indices.get_block_type_name(0xFFFF)

    def test_block_type_names_dict(self):
        """Test BLOCK_TYPE_NAMES dictionary."""
        assert indices.BLOCK_TYPE_NAMES[indices.BLOCK_IM0] == "I&M0"
        assert indices.BLOCK_TYPE_NAMES[indices.BLOCK_AR_DATA] == "ARData"
        assert indices.BLOCK_TYPE_NAMES[indices.BLOCK_LOG_DATA] == "LogData"


class TestAlign4:
    """Tests for the align4 helper function."""

    def test_align4_already_aligned(self):
        """Test align4 with already aligned values."""
        assert blocks.align4(0) == 0
        assert blocks.align4(4) == 4
        assert blocks.align4(8) == 8

    def test_align4_needs_padding(self):
        """Test align4 with values needing padding."""
        assert blocks.align4(1) == 4
        assert blocks.align4(2) == 4
        assert blocks.align4(3) == 4
        assert blocks.align4(5) == 8
        assert blocks.align4(6) == 8
        assert blocks.align4(7) == 8


# =============================================================================
# Integration Tests with Real Device Data
# =============================================================================


class TestRealDeviceData:
    """Tests using captured data from real PROFINET devices (anonymized)."""

    # PDRealData sample (anonymized - device names replaced)
    PDREALDATA_SAMPLE = bytes.fromhex(
        # MultipleBlockHeader for interface (slot 0, subslot 0x8000)
        "04000090"  # type=0x0400, length=0x0090
        "01000000"  # version 1.0, padding
        "00000000"  # API = 0
        "00008000"  # slot=0, subslot=0x8000
        # Nested PDInterfaceDataReal (0x0240)
        "0240"  # type
        "0024"  # length
        "0100"  # version
        "0a"  # chassis_id len = 10
        "41414141414141414141"  # "AAAAAAAAAA" (anonymized)
        "0000"  # padding
        "001122334455"  # MAC (anonymized)
        "0000"  # padding
        "c0a80164"  # IP: 192.168.1.100
        "ffffff00"  # Subnet: 255.255.255.0
        "c0a80101"  # Gateway: 192.168.1.1
    )

    def test_parse_real_pdrealdata_sample(self):
        """Test parsing simplified real device PDRealData."""
        # Note: This is a simplified sample, real data would be longer
        result = blocks.parse_pd_real_data(self.PDREALDATA_SAMPLE)

        # Should have at least one slot discovered
        assert len(result.slots) >= 1

        # First slot should be interface (subslot 0x8000)
        if result.slots:
            assert result.slots[0].subslot == 0x8000

    # RealIdentificationData sample (version 1.1, anonymized)
    REAL_ID_SAMPLE = bytes.fromhex(
        "00130046"  # type=0x0013, length=0x0046
        "0101"  # version 1.1
        "0001"  # NumAPIs = 1
        "00000000"  # API = 0
        "0003"  # NumSlots = 3
        # Slot 0
        "0000"  # SlotNumber = 0
        "00010001"  # ModuleIdent
        "0003"  # NumSubslots = 3
        "0001" "00000001"  # Subslot 1
        "8000" "00000002"  # Subslot 0x8000
        "8001" "00000003"  # Subslot 0x8001
        # Slot 1
        "0001"  # SlotNumber = 1
        "00020002"  # ModuleIdent
        "0001"  # NumSubslots = 1
        "0001" "00000001"  # Subslot 1
        # Slot 2
        "0002"  # SlotNumber = 2
        "00030003"  # ModuleIdent
        "0001"  # NumSubslots = 1
        "0001" "00000001"  # Subslot 1
    )

    def test_parse_real_identification_sample(self):
        """Test parsing real device RealIdentificationData."""
        result = blocks.parse_real_identification_data(self.REAL_ID_SAMPLE)

        assert result.version == (1, 1)
        # Should find 5 slot/subslot combinations (3+1+1)
        assert len(result.slots) == 5

        # Check first slot (slot 0, subslot 1)
        assert result.slots[0].slot == 0
        assert result.slots[0].subslot == 1
        assert result.slots[0].api == 0

        # Check interface subslot (slot 0, subslot 0x8000)
        assert result.slots[1].subslot == 0x8000

        # Check port subslot (slot 0, subslot 0x8001)
        assert result.slots[2].subslot == 0x8001
