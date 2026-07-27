from dataclasses import dataclass
from enum import Enum
from struct import calcsize, pack, unpack_from
from typing import Callable, Optional, Type, Union

from typing_extensions import Self

from .abstract import BaseClass
from .exceptions import SPSDKError


@dataclass(frozen=True)
class SpsdkEnumMember:
    """SPSDK Enum member representation.

    This class represents a single member of an SPSDK enumeration, containing
    the numeric tag, human-readable label, and optional description for the
    enumeration value.
    """

    tag: int
    label: str
    description: Optional[str] = None


class SpsdkEnum(SpsdkEnumMember, Enum):
    """SPSDK enhanced enumeration with extended functionality.

    This class extends Python's standard Enum to provide additional features
    for SPSDK operations including tag-based identification, label management,
    and flexible member lookup capabilities. It supports equality comparison
    by both tag and label values, and provides utility methods for member
    introspection and validation.
    """

    def __eq__(self, __value: object) -> bool:
        """Check equality of enum value with another object.

        Compares the enum instance with another object by checking if the object
        matches either the tag or label attribute of this enum value.

        :param __value: Object to compare with this enum value.
        :return: True if the object equals tag or label, False otherwise.
        """
        return self.tag == __value or self.label == __value

    def __hash__(self) -> int:
        """Calculate hash value for the enum instance.

        The hash is computed based on the combination of tag, label, and description
        attributes to ensure unique identification of enum instances.

        :return: Hash value as integer.
        """
        return hash((self.tag, self.label, self.description))

    @classmethod
    def labels(cls) -> list[str]:
        """Get list of labels of all enum members.

        :return: List of all labels.
        """
        return [value.label for value in cls.__members__.values()]

    @classmethod
    def tags(cls) -> list[int]:
        """Get list of tags of all enum members.

        :return: List of all tags.
        """
        return [value.tag for value in cls.__members__.values()]

    @classmethod
    def contains(cls, obj: Union[int, str]) -> bool:
        """Check if given member with given tag/label exists in enum.

        :param obj: Label or tag of enum member to check for existence.
        :raises SPSDKError: Object must be either string or integer.
        :return: True if member exists, False otherwise.
        """
        if not isinstance(obj, (int, str)):
            raise SPSDKError("Object must be either string or integer")
        try:
            cls.from_attr(obj)
            return True
        except SPSDKError:
            return False

    @classmethod
    def get_tag(cls, label: str) -> int:
        """Get tag of enum member with given label.

        :param label: Label to be used for searching.
        :raises SPSDKValueError: If enum member with given label is not found.
        :return: Tag of found enum member.
        """
        value = cls.from_label(label)
        return value.tag

    @classmethod
    def get_label(cls, tag: int) -> str:
        """Get label of enum member with given tag.

        :param tag: Tag to be used for searching.
        :return: Label of found enum member.
        """
        value = cls.from_tag(tag)
        return value.label

    @classmethod
    def get_description(cls, tag: int, default: Optional[str] = None) -> Optional[str]:
        """Get description of enum member with given tag.

        :param tag: Tag to be used for searching.
        :param default: Default value if member contains no description.
        :return: Description of found enum member or default value if no description exists.
        """
        value = cls.from_tag(tag)
        return value.description or default

    @classmethod
    def from_attr(cls, attribute: Union[int, str]) -> Self:
        """Get enum member with given tag/label attribute.

        The method automatically determines whether to use tag (for int) or label (for str)
        based on the attribute type and delegates to the appropriate method.

        :param attribute: Tag value (int) or label value (str) of the enum member to find.
        :return: Found enum member matching the given attribute.
        """
        # Let's make MyPy happy, see https://github.com/python/mypy/issues/10740
        from_tag: Callable = cls.from_tag
        from_label: Callable = cls.from_label
        from_method: Callable = from_tag if isinstance(attribute, int) else from_label
        return from_method(attribute)

    @classmethod
    def from_tag(cls, tag: int) -> Self:
        """Get enum member with given tag.

        :param tag: Tag to be used for searching
        :raises SPSDKError: If enum with given tag is not found
        :return: Found enum member
        """
        for item in cls.__members__.values():
            if item.tag == tag:
                return item
        raise SPSDKError(f"There is no {cls.__name__} item in with tag {tag} defined")

    @classmethod
    def from_label(cls, label: str) -> Self:
        """Get enum member with given label.

        The method performs case-insensitive search through all enum members to find
        the one with matching label.

        :param label: Label to be used for searching
        :raises SPSDKError: If enum with given label is not found or label is not string
        :return: Found enum member
        """
        if not isinstance(label, str):
            raise SPSDKError("Label must be string")
        for item in cls.__members__.values():
            if item.label.upper() == label.upper():
                return item
        raise SPSDKError(f"There is no {cls.__name__} item with label {label} defined")

    @classmethod
    def create_from_dict(cls, name: str, config: dict[str, Union[tuple, list]]) -> Type[Self]:
        """Create the Enum in runtime from the Dictionary configuration.

        The method dynamically creates an Enum class using the provided name and configuration
        dictionary. All dictionary values are converted to tuples before creating the Enum.

        :param name: Name of the new Enum class to be created.
        :param config: Configuration dictionary containing enum definitions where values can be
            tuples or lists.
        :return: Dynamically created Enum class.
        """
        updated_config = {}
        for k, v in config.items():
            updated_config[k] = tuple(v)
        return cls(name, updated_config)  # type: ignore # pylint: disable=too-many-function-args


########################################################################################################################
# Enums
########################################################################################################################
class EnumCmdTag(SpsdkEnum):
    """SB2 command tag enumeration.

    This enumeration defines all supported command tags used in SB2 (Secure Binary 2) files
    for bootloader operations including memory management, execution control, and security
    functions.
    """

    NOP = (0x0, "NOP")
    TAG = (0x1, "TAG")
    LOAD = (0x2, "LOAD")
    FILL = (0x3, "FILL")
    JUMP = (0x4, "JUMP")
    CALL = (0x5, "CALL")
    ERASE = (0x7, "ERASE")
    RESET = (0x8, "RESET")
    MEM_ENABLE = (0x9, "MEM_ENABLE")
    PROG = (0xA, "PROG")
    FW_VERSION_CHECK = (0xB, "FW_VERSION_CHECK", "Check FW version fuse value")
    WR_KEYSTORE_TO_NV = (
        0xC,
        "WR_KEYSTORE_TO_NV",
        "Restore key-store restore to non-volatile memory",
    )
    WR_KEYSTORE_FROM_NV = (0xD, "WR_KEYSTORE_FROM_NV", "Backup key-store from non-volatile memory")


########################################################################################################################
# Header Class
########################################################################################################################
class CmdHeader(BaseClass):
    """SBFile command header for SB2 format.

    This class represents a command header structure used in SB2 (Secure Binary) files,
    providing functionality to create, validate, and export command headers with
    proper CRC calculation and binary formatting.

    :cvar FORMAT: Binary format string for struct packing/unpacking.
    :cvar SIZE: Size of the header structure in bytes.
    """

    FORMAT = "<2BH3L"
    SIZE = calcsize(FORMAT)

    @property
    def crc(self) -> int:
        """Calculate CRC for the header data.

        Computes a checksum using a custom algorithm that starts with 0x5A and
        adds each byte from the raw data (excluding the first byte) with overflow
        handling to maintain 8-bit values.

        :return: Calculated CRC checksum as an 8-bit integer value.
        """
        raw_data = self._raw_data(crc=0)
        checksum = 0x5A
        for i in range(1, self.SIZE):
            checksum = (checksum + raw_data[i]) & 0xFF
        return checksum

    def __init__(self, tag: int, flags: int = 0, zero_filling: bool = False) -> None:
        """Initialize SB2 command header with specified parameters.

        Creates a new command header instance with the given tag and optional flags.
        Initializes all header fields to default values and validates the command tag.

        :param tag: Command tag identifier from EnumCmdTag enumeration
        :param flags: Optional command flags, defaults to 0
        :param zero_filling: Enable zero filling for the command, defaults to False
        :raises SPSDKError: Invalid command tag not found in EnumCmdTag
        """
        if tag not in EnumCmdTag.tags():
            raise SPSDKError("Incorrect command tag")
        self.tag = tag
        self.flags = flags
        self.address = 0
        self.count = 0
        self.data = 0
        self.zero_filling = zero_filling

    def __repr__(self) -> str:
        """Return string representation of SB2 command header.

        This method provides a human-readable string representation of the SB2 command header,
        displaying the command tag for debugging and logging purposes.

        :return: String representation containing the command tag.
        """
        return f"SB2 Command header, TAG:{self.tag}"

    def __str__(self) -> str:
        """Return string representation of the command.

        Provides a formatted string containing the command's tag, flags, address, count, and data values.
        The tag is displayed as a human-readable label if available, otherwise as hexadecimal.

        :return: Formatted string with command details including tag, flags, address, count and data.
        """
        tag = (
            EnumCmdTag.get_label(self.tag) if self.tag in EnumCmdTag.tags() else f"0x{self.tag:02X}"
        )
        return (
            f"tag={tag}, flags=0x{self.flags:04X}, "
            f"address=0x{self.address:08X}, count=0x{self.count:08X}, data=0x{self.data:08X}"
        )

    def _raw_data(self, crc: int) -> bytes:
        """Return raw data of the header with specified CRC.

        The method packs the header data into binary format using the defined FORMAT structure,
        including the provided CRC value along with tag, flags, address, count, and data fields.

        :param crc: CRC value to be included in the header.
        :return: Binary representation of the header as bytes.
        """
        return pack(self.FORMAT, crc, self.tag, self.flags, self.address, self.count, self.data)

    def export(self) -> bytes:
        """Export command header as bytes.

        Serializes the command header data including CRC into a byte representation
        suitable for transmission or storage.

        :return: Raw byte data of the command header with CRC.
        """
        return self._raw_data(self.crc)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command header from bytes array.

        The method unpacks binary data into a CMDHeader object and validates
        the CRC checksum to ensure data integrity.

        :param data: Input binary data containing the command header.
        :return: Parsed CMDHeader object with populated fields.
        :raises SPSDKError: Raised when input data size is insufficient.
        :raises SPSDKError: Raised when CRC checksum validation fails.
        """
        if calcsize(cls.FORMAT) > len(data):
            raise SPSDKError("Incorrect size")
        obj = cls(EnumCmdTag.NOP.tag)
        crc, obj.tag, obj.flags, obj.address, obj.count, obj.data = unpack_from(cls.FORMAT, data)
        if crc != obj.crc:
            raise SPSDKError("CRC does not match")
        return obj


########################################################################################################################
# Commands Classes
########################################################################################################################
class CmdBaseClass(BaseClass):
    """Base class for all SB2 commands.

    This class provides the foundation for all Secure Binary 2.0 command implementations,
    managing common command structure including headers and basic serialization functionality.

    :cvar ROM_MEM_DEVICE_ID_MASK: Bit mask for extracting device ID from flags.
    :cvar ROM_MEM_DEVICE_ID_SHIFT: Bit shift value for device ID within flags.
    :cvar ROM_MEM_GROUP_ID_MASK: Bit mask for extracting group ID from flags.
    :cvar ROM_MEM_GROUP_ID_SHIFT: Bit shift value for group ID within flags.
    """

    # bit mask for device ID inside flags
    ROM_MEM_DEVICE_ID_MASK = 0xFF00
    # shift for device ID inside flags
    ROM_MEM_DEVICE_ID_SHIFT = 8
    # bit mask for group ID inside flags
    ROM_MEM_GROUP_ID_MASK = 0xF0
    # shift for group ID inside flags
    ROM_MEM_GROUP_ID_SHIFT = 4

    def __init__(self, tag: EnumCmdTag) -> None:
        """Initialize CmdBase.

        :param tag: Command tag enumeration value used to set the header tag.
        """
        self._header = CmdHeader(tag.tag)

    @property
    def header(self) -> CmdHeader:
        """Return command header.

        :return: Command header object containing header information.
        """
        return self._header

    @property
    def raw_size(self) -> int:
        """Return size of the command in binary format (including header).

        :return: Size of the command in bytes, defaults to header size only.
        """
        return CmdHeader.SIZE  # this is default implementation

    def __repr__(self) -> str:
        """Return string representation of the command.

        This method provides a default implementation that displays the command type
        followed by the header information.

        :return: String representation showing "Command: " followed by the header.
        """
        return "Command: " + str(self._header)  # default implementation: use command name

    def __str__(self) -> str:
        """Return text info about the instance.

        :return: String representation of the instance with newline character.
        """
        return repr(self) + "\n"  # default implementation is same as __repr__

    def export(self) -> bytes:
        """Export object as serialized byte representation.

        This method provides the default implementation for object serialization
        by delegating to the header's export functionality.

        :return: Serialized object data as bytes.
        """
        return self._header.export()  # default implementation
