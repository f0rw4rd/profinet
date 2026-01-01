"""
PROFINET IO-Controller Library

A Python library for PROFINET IO communication, supporting:
- DCP (Discovery and Configuration Protocol) for device discovery
- DCE/RPC for acyclic parameter read/write operations
- IM0/IM1 device identification data access

This library acts as an IO-Controller, allowing connection to and
communication with PROFINET IO-Devices.

Credits:
    Original implementation by Alfred Krohmer (2015)
    https://github.com/alfredkrohmer/profinet

    Modernized for Python 3.8+ by f0rw4rd (2024)
    https://github.com/f0rw4rd/profinet-py
"""

from .protocol import (
    EthernetHeader,
    EthernetVLANHeader,
    PNDCPHeader,
    PNDCPBlock,
    PNDCPBlockRequest,
    IPConfiguration,
    PNRPCHeader,
    PNNRDData,
    PNIODHeader,
    PNBlockHeader,
    PNARBlockRequest,
    PNIODReleaseBlock,
    PNInM0,
    PNInM1,
    PNInM2,
    PNInM3,
    PNInM4,
    PNInM5,
)

from .dcp import (
    # Classes
    DCPDeviceDescription,
    DCPResponseCode,
    DCPDHCPBlock,
    DCPLLDPBlock,
    IPBlockInfo,
    BlockQualifier,
    ResetQualifier,
    DeviceInitiative,
    # Functions
    send_discover,
    send_request,
    read_response,
    send_hello,
    receive_hello,
    get_param,
    set_param,
    set_ip,
    signal_device,
    reset_to_factory,
    # Frame IDs
    DCP_IDENTIFY_FRAME_ID,
    DCP_GET_SET_FRAME_ID,
    DCP_HELLO_FRAME_ID,
    # Service IDs
    DCP_SERVICE_ID_GET,
    DCP_SERVICE_ID_SET,
    DCP_SERVICE_ID_IDENTIFY,
    DCP_SERVICE_ID_HELLO,
    # Service Types
    DCP_SERVICE_TYPE_REQUEST,
    DCP_SERVICE_TYPE_RESPONSE_SUCCESS,
    DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED,
    # Options
    DCP_MAX_NAME_LENGTH,
    DCP_OPTION_IP,
    DCP_OPTION_DEVICE,
    DCP_OPTION_DHCP,
    DCP_OPTION_LLDP,
    DCP_OPTION_CONTROL,
    DCP_OPTION_DEVICE_INITIATIVE,
    DCP_OPTION_NME,
    DCP_OPTION_ALL,
    # Manufacturer options
    DCP_OPTION_MANUF_MIN,
    DCP_OPTION_MANUF_MAX,
    # DHCP suboptions
    DCP_SUBOPTION_DHCP_HOSTNAME,
    DCP_SUBOPTION_DHCP_VENDOR_SPEC,
    DCP_SUBOPTION_DHCP_SERVER_ID,
    DCP_SUBOPTION_DHCP_PARAM_REQ,
    DCP_SUBOPTION_DHCP_CLASS_ID,
    DCP_SUBOPTION_DHCP_CLIENT_ID,
    DCP_SUBOPTION_DHCP_FQDN,
    DCP_SUBOPTION_DHCP_UUID,
    DCP_SUBOPTION_DHCP_CONTROL,
    # LLDP suboptions
    DCP_SUBOPTION_LLDP_PORT_ID,
    DCP_SUBOPTION_LLDP_CHASSIS_ID,
    DCP_SUBOPTION_LLDP_TTL,
    DCP_SUBOPTION_LLDP_PORT_DESC,
    DCP_SUBOPTION_LLDP_SYSTEM_NAME,
    DCP_SUBOPTION_LLDP_SYSTEM_DESC,
    DCP_SUBOPTION_LLDP_SYSTEM_CAP,
    DCP_SUBOPTION_LLDP_MGMT_ADDR,
    # Device Initiative suboption
    DCP_SUBOPTION_DEVICE_INITIATIVE,
    # Legacy reset modes
    RESET_MODE_COMMUNICATION,
    RESET_MODE_APPLICATION,
    RESET_MODE_ENGINEERING,
    RESET_MODE_ALL_DATA,
    RESET_MODE_DEVICE,
    RESET_MODE_FACTORY,
)

from .rpc import (
    RPCCon,
    get_station_info,
    epm_lookup,
    # Data classes
    PortStatistics,
    LinkData,
    PortInfo,
    InterfaceInfo,
    DiagnosisEntry,
    ARInfo,
    LogEntry,
    EPMEndpoint,
    MAU_TYPES,
    # IOCR setup classes
    IOSlot,
    IOCRSetup,
    ConnectResult,
    # Python timing constants
    PYTHON_MIN_CYCLE_TIME_MS,
    PYTHON_SAFE_CYCLE_TIME_MS,
    # RPC Constants
    RPC_PORT,
    RPC_BIND_PORT,
    UUID_NULL,
    UUID_EPM_V4,
    UUID_PNIO_DEVICE,
    UUID_PNIO_CONTROLLER,
    PNIO_DEVICE_INTERFACE_VERSION,
)

from .diagnosis import (
    # Diagnosis data classes
    DiagnosisData,
    ChannelDiagnosis,
    ExtChannelDiagnosis,
    QualifiedChannelDiagnosis,
    ChannelProperties,
    # Enums
    UserStructureIdentifier,
    ChannelType,
    ChannelDirection,
    ChannelAccumulative,
    ChannelSpecifier,
    # Parsing functions
    parse_diagnosis_block,
    parse_diagnosis_simple,
    decode_channel_error_type,
    decode_ext_channel_error_type,
    # Constants
    CHANNEL_ERROR_TYPES,
    EXT_CHANNEL_ERROR_TYPES_MAP,
)

from .util import (
    ethernet_socket,
    udp_socket,
    get_mac,
    s2mac,
    mac2s,
    s2ip,
    ip2s,
    to_hex,
)

from .vendors import (
    profinet_vendor_map,
    get_vendor_name,
    lookup_vendor,
)

from . import indices
from . import blocks

from .blocks import (
    # Data classes for block parsing
    BlockHeader,
    SlotInfo,
    PeerInfo,
    PDRealData,
    RealIdentificationData,
    # ModuleDiff
    ModuleDiffBlock,
    ModuleDiffModule,
    ModuleDiffSubmodule,
    # WriteMultiple
    WriteMultipleResult,
    IODWriteMultipleBuilder,
    # ExpectedSubmodule
    ExpectedSubmoduleBlockReq,
    ExpectedSubmoduleAPI,
    ExpectedSubmodule,
    ExpectedSubmoduleDataDescription,
    # Parsing functions
    parse_block_header,
    parse_multiple_block_header,
    parse_pd_interface_data_real,
    parse_pd_port_data_real,
    parse_pd_real_data,
    parse_real_identification_data,
    parse_port_statistics,
    parse_module_diff_block,
    parse_write_multiple_response,
)

from .alarms import (
    # Alarm item types
    AlarmItem,
    DiagnosisItem,
    MaintenanceItem,
    UploadRetrievalItem,
    iParameterItem,
    PE_AlarmItem,
    RS_AlarmItem,
    PRAL_AlarmItem,
    # Alarm notification
    AlarmNotification,
    # Parsing functions
    parse_alarm_notification,
    parse_alarm_item,
)

from .alarm_listener import (
    AlarmListener,
    AlarmEndpoint,
)

from .rt import (
    RTFrame,
    IOCRConfig,
    IODataObject,
    CyclicDataBuilder,
    IOCR_TYPE_INPUT,
    IOCR_TYPE_OUTPUT,
    RT_CLASS_1,
    IOXS_GOOD,
    IOXS_BAD,
)

from .cyclic import (
    CyclicController,
    CyclicStats,
)

from .device import (
    ProfinetDevice,
    DeviceInfo,
    WriteItem,
    scan,
    scan_dict,
)

from .exceptions import (
    ProfinetError,
    DCPError,
    DCPTimeoutError,
    DCPDeviceNotFoundError,
    RPCError,
    RPCTimeoutError,
    RPCFaultError,
    RPCConnectionError,
    PNIOError,
    ValidationError,
    InvalidMACError,
    InvalidIPError,
    SocketError,
    PermissionDeniedError,
)

__version__ = "0.3.0"
__all__ = [
    # Protocol structures
    "EthernetHeader",
    "EthernetVLANHeader",
    "PNDCPHeader",
    "PNDCPBlock",
    "PNDCPBlockRequest",
    "IPConfiguration",
    "PNRPCHeader",
    "PNNRDData",
    "PNIODHeader",
    "PNBlockHeader",
    "PNARBlockRequest",
    "PNIODReleaseBlock",
    "PNInM0",
    "PNInM1",
    "PNInM2",
    "PNInM3",
    "PNInM4",
    "PNInM5",
    # DCP classes
    "DCPDeviceDescription",
    "DCPResponseCode",
    "DCPDHCPBlock",
    "DCPLLDPBlock",
    "IPBlockInfo",
    "BlockQualifier",
    "ResetQualifier",
    "DeviceInitiative",
    # DCP functions
    "send_discover",
    "send_request",
    "read_response",
    "send_hello",
    "receive_hello",
    "get_param",
    "set_param",
    "set_ip",
    "signal_device",
    "reset_to_factory",
    # DCP Frame IDs
    "DCP_IDENTIFY_FRAME_ID",
    "DCP_GET_SET_FRAME_ID",
    "DCP_HELLO_FRAME_ID",
    # DCP Service IDs
    "DCP_SERVICE_ID_GET",
    "DCP_SERVICE_ID_SET",
    "DCP_SERVICE_ID_IDENTIFY",
    "DCP_SERVICE_ID_HELLO",
    # DCP Service Types
    "DCP_SERVICE_TYPE_REQUEST",
    "DCP_SERVICE_TYPE_RESPONSE_SUCCESS",
    "DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED",
    # DCP Options
    "DCP_MAX_NAME_LENGTH",
    "DCP_OPTION_IP",
    "DCP_OPTION_DEVICE",
    "DCP_OPTION_DHCP",
    "DCP_OPTION_LLDP",
    "DCP_OPTION_CONTROL",
    "DCP_OPTION_DEVICE_INITIATIVE",
    "DCP_OPTION_NME",
    "DCP_OPTION_ALL",
    "DCP_OPTION_MANUF_MIN",
    "DCP_OPTION_MANUF_MAX",
    # DCP DHCP suboptions
    "DCP_SUBOPTION_DHCP_HOSTNAME",
    "DCP_SUBOPTION_DHCP_VENDOR_SPEC",
    "DCP_SUBOPTION_DHCP_SERVER_ID",
    "DCP_SUBOPTION_DHCP_PARAM_REQ",
    "DCP_SUBOPTION_DHCP_CLASS_ID",
    "DCP_SUBOPTION_DHCP_CLIENT_ID",
    "DCP_SUBOPTION_DHCP_FQDN",
    "DCP_SUBOPTION_DHCP_UUID",
    "DCP_SUBOPTION_DHCP_CONTROL",
    # DCP LLDP suboptions
    "DCP_SUBOPTION_LLDP_PORT_ID",
    "DCP_SUBOPTION_LLDP_CHASSIS_ID",
    "DCP_SUBOPTION_LLDP_TTL",
    "DCP_SUBOPTION_LLDP_PORT_DESC",
    "DCP_SUBOPTION_LLDP_SYSTEM_NAME",
    "DCP_SUBOPTION_LLDP_SYSTEM_DESC",
    "DCP_SUBOPTION_LLDP_SYSTEM_CAP",
    "DCP_SUBOPTION_LLDP_MGMT_ADDR",
    # DCP DeviceInitiative suboption
    "DCP_SUBOPTION_DEVICE_INITIATIVE",
    # Reset modes (legacy)
    "RESET_MODE_COMMUNICATION",
    "RESET_MODE_APPLICATION",
    "RESET_MODE_ENGINEERING",
    "RESET_MODE_ALL_DATA",
    "RESET_MODE_DEVICE",
    "RESET_MODE_FACTORY",
    # RPC
    "RPCCon",
    "get_station_info",
    "epm_lookup",
    "EPMEndpoint",
    # IOCR setup classes
    "IOSlot",
    "IOCRSetup",
    "ConnectResult",
    # Python timing constants
    "PYTHON_MIN_CYCLE_TIME_MS",
    "PYTHON_SAFE_CYCLE_TIME_MS",
    # RPC constants
    "RPC_PORT",
    "RPC_BIND_PORT",
    "UUID_NULL",
    "UUID_EPM_V4",
    "UUID_PNIO_DEVICE",
    "UUID_PNIO_CONTROLLER",
    "PNIO_DEVICE_INTERFACE_VERSION",
    # Utilities
    "ethernet_socket",
    "udp_socket",
    "get_mac",
    "s2mac",
    "mac2s",
    "s2ip",
    "ip2s",
    "to_hex",
    # Vendor lookup
    "profinet_vendor_map",
    "get_vendor_name",
    "lookup_vendor",
    # Diagnosis
    "DiagnosisData",
    "ChannelDiagnosis",
    "ExtChannelDiagnosis",
    "QualifiedChannelDiagnosis",
    "ChannelProperties",
    "UserStructureIdentifier",
    "ChannelType",
    "ChannelDirection",
    "ChannelAccumulative",
    "ChannelSpecifier",
    "parse_diagnosis_block",
    "parse_diagnosis_simple",
    "decode_channel_error_type",
    "decode_ext_channel_error_type",
    "CHANNEL_ERROR_TYPES",
    "EXT_CHANNEL_ERROR_TYPES_MAP",
    # Blocks module
    "BlockHeader",
    "SlotInfo",
    "PeerInfo",
    "PDRealData",
    "RealIdentificationData",
    "ModuleDiffBlock",
    "ModuleDiffModule",
    "ModuleDiffSubmodule",
    "WriteMultipleResult",
    "IODWriteMultipleBuilder",
    "ExpectedSubmoduleBlockReq",
    "ExpectedSubmoduleAPI",
    "ExpectedSubmodule",
    "ExpectedSubmoduleDataDescription",
    "parse_block_header",
    "parse_multiple_block_header",
    "parse_pd_interface_data_real",
    "parse_pd_port_data_real",
    "parse_pd_real_data",
    "parse_real_identification_data",
    "parse_port_statistics",
    "parse_module_diff_block",
    "parse_write_multiple_response",
    # Alarms module
    "AlarmItem",
    "DiagnosisItem",
    "MaintenanceItem",
    "UploadRetrievalItem",
    "iParameterItem",
    "PE_AlarmItem",
    "RS_AlarmItem",
    "PRAL_AlarmItem",
    "AlarmNotification",
    "parse_alarm_notification",
    "parse_alarm_item",
    # Alarm listener
    "AlarmListener",
    "AlarmEndpoint",
    # Real-time (cyclic IO)
    "RTFrame",
    "IOCRConfig",
    "IODataObject",
    "CyclicDataBuilder",
    "CyclicController",
    "CyclicStats",
    "IOCR_TYPE_INPUT",
    "IOCR_TYPE_OUTPUT",
    "RT_CLASS_1",
    "IOXS_GOOD",
    "IOXS_BAD",
    # Device module (high-level API)
    "ProfinetDevice",
    "DeviceInfo",
    "WriteItem",
    "scan",
    "scan_dict",
    # Exceptions
    "ProfinetError",
    "DCPError",
    "DCPTimeoutError",
    "DCPDeviceNotFoundError",
    "RPCError",
    "RPCTimeoutError",
    "RPCFaultError",
    "RPCConnectionError",
    "PNIOError",
    "ValidationError",
    "InvalidMACError",
    "InvalidIPError",
    "SocketError",
    "PermissionDeniedError",
]
