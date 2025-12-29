"""
PROFINET Block Parsing Module.

Provides data classes and parsing functions for PROFINET block structures
extracted from the Wireshark pn_io dissector.

Block structures follow the standard format:
- BlockHeader (6 bytes): Type, Length, Version
- Variable body depending on block type
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import struct

from . import indices


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class BlockHeader:
    """PROFINET block header (6 bytes)."""

    block_type: int
    block_length: int  # Includes version (2 bytes), body = length - 2
    version_high: int
    version_low: int

    @property
    def body_length(self) -> int:
        """Length of block body (excluding version bytes)."""
        return self.block_length - 2 if self.block_length >= 2 else 0

    @property
    def type_name(self) -> str:
        """Human-readable block type name."""
        return indices.get_block_type_name(self.block_type)


@dataclass
class SlotInfo:
    """Slot/subslot discovered from device."""

    slot: int
    subslot: int
    api: int = 0
    module_ident: int = 0
    submodule_ident: int = 0
    blocks: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"SlotInfo(api={self.api}, slot={self.slot}, subslot=0x{self.subslot:04X})"


@dataclass
class PeerInfo:
    """LLDP peer information from PDPortDataReal."""

    port_id: str
    chassis_id: str
    mac_address: bytes

    @property
    def mac_str(self) -> str:
        """MAC address as colon-separated string."""
        return ":".join(f"{b:02x}" for b in self.mac_address)


@dataclass
class PortInfo:
    """Port information from PDPortDataReal (0x020F)."""

    slot: int
    subslot: int
    port_id: str
    mau_type: int
    link_state_port: int
    link_state_link: int
    media_type: int
    peers: List[PeerInfo] = field(default_factory=list)
    domain_boundary: int = 0
    multicast_boundary: int = 0

    @property
    def mau_type_name(self) -> str:
        """Human-readable MAU type."""
        from .rpc import MAU_TYPES

        return MAU_TYPES.get(self.mau_type, f"Unknown({self.mau_type})")

    @property
    def link_state(self) -> str:
        """Human-readable link state."""
        states = {0: "Unknown", 1: "Up", 2: "Down", 3: "Testing"}
        return states.get(self.link_state_link, f"Unknown({self.link_state_link})")


@dataclass
class InterfaceInfo:
    """Interface information from PDInterfaceDataReal (0x0240)."""

    chassis_id: str
    mac_address: bytes
    ip_address: bytes
    subnet_mask: bytes
    gateway: bytes

    @property
    def mac_str(self) -> str:
        """MAC address as colon-separated string."""
        return ":".join(f"{b:02x}" for b in self.mac_address)

    @property
    def ip_str(self) -> str:
        """IP address as dotted string."""
        return ".".join(str(b) for b in self.ip_address)

    @property
    def subnet_str(self) -> str:
        """Subnet mask as dotted string."""
        return ".".join(str(b) for b in self.subnet_mask)

    @property
    def gateway_str(self) -> str:
        """Gateway as dotted string."""
        return ".".join(str(b) for b in self.gateway)


@dataclass
class PDRealData:
    """Parsed PDRealData (0xF841) structure."""

    slots: List[SlotInfo] = field(default_factory=list)
    interface: Optional[InterfaceInfo] = None
    ports: List[PortInfo] = field(default_factory=list)
    raw_blocks: List[Tuple[int, int, int, bytes]] = field(
        default_factory=list
    )  # (api, slot, subslot, data)


@dataclass
class RealIdentificationData:
    """Parsed RealIdentificationData (0xF000/0x0013) structure."""

    slots: List[SlotInfo] = field(default_factory=list)
    version: Tuple[int, int] = (1, 0)


# =============================================================================
# Parsing Functions
# =============================================================================


def parse_block_header(data: bytes, offset: int = 0) -> Tuple[BlockHeader, int]:
    """
    Parse a 6-byte PROFINET block header.

    Args:
        data: Raw bytes containing the block
        offset: Starting offset in data

    Returns:
        Tuple of (BlockHeader, new_offset after header)

    Raises:
        ValueError: If data is too short
    """
    if len(data) < offset + 6:
        raise ValueError(f"Block header requires 6 bytes, got {len(data) - offset}")

    block_type, block_length, ver_high, ver_low = struct.unpack_from(
        ">HHBb", data, offset
    )

    header = BlockHeader(
        block_type=block_type,
        block_length=block_length,
        version_high=ver_high,
        version_low=ver_low,
    )

    return header, offset + 6


def align4(offset: int) -> int:
    """Align offset to 4-byte boundary."""
    return (offset + 3) & ~3


def parse_multiple_block_header(
    data: bytes, offset: int = 0
) -> Tuple[int, int, int, int]:
    """
    Parse MultipleBlockHeader (0x0400) body.

    Format:
        Padding (2 bytes to align to 4)
        API (uint32 BE)
        SlotNr (uint16 BE)
        SubslotNr (uint16 BE)

    Args:
        data: Raw bytes (body after block header)
        offset: Starting offset

    Returns:
        Tuple of (api, slot, subslot, body_offset where nested blocks start)
    """
    # Skip 2-byte padding after header
    offset += 2

    if len(data) < offset + 8:
        raise ValueError(f"MultipleBlockHeader body requires 8 bytes after padding")

    api, slot, subslot = struct.unpack_from(">IHH", data, offset)

    return api, slot, subslot, offset + 8


def parse_pd_interface_data_real(data: bytes, offset: int = 0, block_header_size: int = 6) -> InterfaceInfo:
    """
    Parse PDInterfaceDataReal (0x0240) block body.

    Format:
        LengthOwnChassisID (uint8)
        OwnChassisID (variable)
        Padding (to 4-byte boundary from block start)
        MACAddress (6 bytes)
        Padding (to 4-byte boundary from block start)
        IPAddress (4 bytes)
        Subnetmask (4 bytes)
        Gateway (4 bytes)

    Args:
        data: Raw bytes (body after block header)
        offset: Starting offset in data
        block_header_size: Size of block header (default 6) for alignment calculation

    Returns:
        InterfaceInfo with parsed data
    """
    start = offset

    def align_from_block(body_offset: int) -> int:
        """Align to 4-byte boundary relative to block start (including header)."""
        block_offset = block_header_size + (body_offset - start)
        aligned_block = align4(block_offset)
        return start + (aligned_block - block_header_size)

    # Read chassis ID length and value
    chassis_len = data[offset]
    offset += 1

    if len(data) < offset + chassis_len:
        raise ValueError(f"Truncated chassis ID")

    chassis_id = data[offset : offset + chassis_len].decode("latin-1", errors="replace")
    offset += chassis_len

    # Align to 4 bytes from block start
    offset = align_from_block(offset)

    # MAC address (6 bytes)
    if len(data) < offset + 6:
        raise ValueError(f"Truncated MAC address")
    mac_address = data[offset : offset + 6]
    offset += 6

    # Align to 4 bytes from block start
    offset = align_from_block(offset)

    # IP, Subnet, Gateway (4 bytes each)
    if len(data) < offset + 12:
        raise ValueError(f"Truncated IP configuration")

    ip_address = data[offset : offset + 4]
    offset += 4
    subnet_mask = data[offset : offset + 4]
    offset += 4
    gateway = data[offset : offset + 4]

    return InterfaceInfo(
        chassis_id=chassis_id,
        mac_address=mac_address,
        ip_address=ip_address,
        subnet_mask=subnet_mask,
        gateway=gateway,
    )


def parse_pd_port_data_real(
    data: bytes, offset: int = 0, slot: int = 0, subslot: int = 0
) -> PortInfo:
    """
    Parse PDPortDataReal (0x020F) block body.

    Format:
        Padding (align to 4)
        SlotNumber (uint16)
        SubslotNumber (uint16)
        LengthOwnPortID (uint8)
        OwnPortID (variable)
        NumberOfPeers (uint8)
        Padding (align to 4)
        [Peer info...]
        MAUType (uint16)
        Padding (align to 4)
        DomainBoundary (uint32)
        MulticastBoundary (uint32)
        LinkStatePort (uint8)
        LinkStateLink (uint8)
        Padding (align to 4)
        MediaType (uint32)

    Args:
        data: Raw bytes (body after block header)
        offset: Starting offset
        slot: Slot number from parent MultipleBlockHeader
        subslot: Subslot number from parent MultipleBlockHeader

    Returns:
        PortInfo with parsed data
    """
    start = offset

    # Padding to align to 4
    offset = align4(offset)

    # Slot/Subslot (may override passed values)
    if len(data) >= offset + 4:
        slot_nr, subslot_nr = struct.unpack_from(">HH", data, offset)
        slot = slot_nr
        subslot = subslot_nr
        offset += 4

    # Port ID
    if len(data) < offset + 1:
        return PortInfo(
            slot=slot, subslot=subslot, port_id="", mau_type=0,
            link_state_port=0, link_state_link=0, media_type=0
        )

    port_id_len = data[offset]
    offset += 1

    if len(data) < offset + port_id_len:
        port_id = ""
    else:
        port_id = data[offset : offset + port_id_len].decode("latin-1", errors="replace")
        offset += port_id_len

    # Number of peers
    num_peers = 0
    peers = []
    if len(data) > offset:
        num_peers = data[offset]
        offset += 1

    # Align
    offset = start + align4(offset - start)

    # Parse peers
    for _ in range(num_peers):
        if len(data) < offset + 1:
            break

        # Peer port ID
        peer_port_len = data[offset]
        offset += 1
        peer_port_id = ""
        if len(data) >= offset + peer_port_len:
            peer_port_id = data[offset : offset + peer_port_len].decode(
                "latin-1", errors="replace"
            )
            offset += peer_port_len

        # Peer chassis ID
        if len(data) < offset + 1:
            break
        peer_chassis_len = data[offset]
        offset += 1
        peer_chassis_id = ""
        if len(data) >= offset + peer_chassis_len:
            peer_chassis_id = data[offset : offset + peer_chassis_len].decode(
                "latin-1", errors="replace"
            )
            offset += peer_chassis_len

        # Align to 4
        offset = start + align4(offset - start)

        # Peer MAC
        peer_mac = b"\x00" * 6
        if len(data) >= offset + 6:
            peer_mac = data[offset : offset + 6]
            offset += 6

        # Align
        offset = start + align4(offset - start)

        peers.append(
            PeerInfo(port_id=peer_port_id, chassis_id=peer_chassis_id, mac_address=peer_mac)
        )

    # MAU type
    mau_type = 0
    if len(data) >= offset + 2:
        (mau_type,) = struct.unpack_from(">H", data, offset)
        offset += 2

    # Align
    offset = start + align4(offset - start)

    # Domain/Multicast boundaries
    domain_boundary = 0
    multicast_boundary = 0
    if len(data) >= offset + 8:
        domain_boundary, multicast_boundary = struct.unpack_from(">II", data, offset)
        offset += 8

    # Link states
    link_state_port = 0
    link_state_link = 0
    if len(data) >= offset + 2:
        link_state_port = data[offset]
        link_state_link = data[offset + 1]
        offset += 2

    # Align
    offset = start + align4(offset - start)

    # Media type
    media_type = 0
    if len(data) >= offset + 4:
        (media_type,) = struct.unpack_from(">I", data, offset)

    return PortInfo(
        slot=slot,
        subslot=subslot,
        port_id=port_id,
        mau_type=mau_type,
        link_state_port=link_state_port,
        link_state_link=link_state_link,
        media_type=media_type,
        peers=peers,
        domain_boundary=domain_boundary,
        multicast_boundary=multicast_boundary,
    )


def parse_pd_real_data(data: bytes) -> PDRealData:
    """
    Parse complete PDRealData (0xF841) response.

    PDRealData contains multiple MultipleBlockHeader blocks, each describing
    a slot/subslot with nested sub-blocks (PDInterfaceDataReal, PDPortDataReal, etc).

    Args:
        data: Raw bytes from reading index 0xF841

    Returns:
        PDRealData with parsed slots, interface, and ports
    """
    result = PDRealData()
    offset = 0

    while offset + 6 <= len(data):
        try:
            header, new_offset = parse_block_header(data, offset)
        except ValueError:
            break

        block_end = new_offset + header.body_length

        if header.block_type == indices.BLOCK_MULTIPLE_HEADER:
            # Parse MultipleBlockHeader to get API/slot/subslot
            try:
                api, slot_nr, subslot_nr, nested_offset = parse_multiple_block_header(
                    data, new_offset
                )

                # Track this slot
                slot_info = SlotInfo(api=api, slot=slot_nr, subslot=subslot_nr)

                # Parse nested blocks within this MultipleBlockHeader
                while nested_offset + 6 <= block_end:
                    try:
                        nested_header, nested_body = parse_block_header(
                            data, nested_offset
                        )
                    except ValueError:
                        break

                    nested_end = nested_body + nested_header.body_length
                    slot_info.blocks.append(nested_header.type_name)

                    # Parse specific block types
                    if nested_header.block_type == indices.BLOCK_PD_INTERFACE_DATA_REAL:
                        try:
                            result.interface = parse_pd_interface_data_real(
                                data, nested_body
                            )
                        except (ValueError, IndexError):
                            pass

                    elif nested_header.block_type == indices.BLOCK_PD_PORT_DATA_REAL:
                        try:
                            port = parse_pd_port_data_real(
                                data, nested_body, slot_nr, subslot_nr
                            )
                            result.ports.append(port)
                        except (ValueError, IndexError):
                            pass

                    nested_offset = nested_end

                result.slots.append(slot_info)
                result.raw_blocks.append(
                    (api, slot_nr, subslot_nr, data[new_offset:block_end])
                )

            except (ValueError, IndexError):
                pass

        offset = block_end

    return result


def parse_real_identification_data(data: bytes) -> RealIdentificationData:
    """
    Parse RealIdentificationData (0xF000 or 0x0013) response.

    Version 1.0:
        NumberOfSlots (uint16)
        For each slot:
            SlotNumber (uint16)
            ModuleIdentNumber (uint32)
            NumberOfSubslots (uint16)
            For each subslot:
                SubslotNumber (uint16)
                SubmoduleIdentNumber (uint32)

    Version 1.1:
        NumberOfAPIs (uint16)
        For each API:
            API (uint32)
            NumberOfSlots (uint16)
            ...same as 1.0

    Args:
        data: Raw bytes from reading index 0xF000

    Returns:
        RealIdentificationData with parsed slot structure
    """
    result = RealIdentificationData()
    offset = 0

    # Parse outer block header if present
    if len(data) >= 6:
        try:
            header, offset = parse_block_header(data, 0)
            result.version = (header.version_high, header.version_low)
        except ValueError:
            offset = 0
            result.version = (1, 0)

    if len(data) < offset + 2:
        return result

    # Version 1.1 has NumberOfAPIs first
    if result.version[0] >= 1 and result.version[1] >= 1:
        (num_apis,) = struct.unpack_from(">H", data, offset)
        offset += 2

        for _ in range(num_apis):
            if len(data) < offset + 6:
                break

            (api,) = struct.unpack_from(">I", data, offset)
            offset += 4

            (num_slots,) = struct.unpack_from(">H", data, offset)
            offset += 2

            for _ in range(num_slots):
                if len(data) < offset + 8:
                    break

                slot_nr, module_ident, num_subslots = struct.unpack_from(
                    ">HIH", data, offset
                )
                offset += 8

                for _ in range(num_subslots):
                    if len(data) < offset + 6:
                        break

                    subslot_nr, submodule_ident = struct.unpack_from(">HI", data, offset)
                    offset += 6

                    result.slots.append(
                        SlotInfo(
                            api=api,
                            slot=slot_nr,
                            subslot=subslot_nr,
                            module_ident=module_ident,
                            submodule_ident=submodule_ident,
                        )
                    )
    else:
        # Version 1.0 - no API level
        (num_slots,) = struct.unpack_from(">H", data, offset)
        offset += 2

        for _ in range(num_slots):
            if len(data) < offset + 8:
                break

            slot_nr, module_ident, num_subslots = struct.unpack_from(">HIH", data, offset)
            offset += 8

            for _ in range(num_subslots):
                if len(data) < offset + 6:
                    break

                subslot_nr, submodule_ident = struct.unpack_from(">HI", data, offset)
                offset += 6

                result.slots.append(
                    SlotInfo(
                        api=0,
                        slot=slot_nr,
                        subslot=subslot_nr,
                        module_ident=module_ident,
                        submodule_ident=submodule_ident,
                    )
                )

    return result


def parse_port_statistics(data: bytes, offset: int = 0) -> Dict[str, int]:
    """
    Parse PDPortStatistic (0x0251) block body.

    Format:
        CounterStatus (uint16)
        ifInOctets (uint32)
        ifOutOctets (uint32)
        ifInDiscards (uint32)
        ifOutDiscards (uint32)
        ifInErrors (uint32)
        ifOutErrors (uint32)

    Args:
        data: Raw bytes (body after block header)
        offset: Starting offset

    Returns:
        Dictionary with counter names and values
    """
    result = {}

    if len(data) < offset + 26:
        return result

    (
        counter_status,
        in_octets,
        out_octets,
        in_discards,
        out_discards,
        in_errors,
        out_errors,
    ) = struct.unpack_from(">HIIIIII", data, offset)

    result = {
        "counter_status": counter_status,
        "in_octets": in_octets,
        "out_octets": out_octets,
        "in_discards": in_discards,
        "out_discards": out_discards,
        "in_errors": in_errors,
        "out_errors": out_errors,
    }

    return result
