#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Miscellaneous functions used throughout the SPSDK."""

import os
import re
from enum import Enum
from math import ceil
from secrets import token_bytes
from typing import Any, Callable, List, Optional, Union

from ..exceptions import SPSDKError, SPSDKValueError

_configuration_cache: dict[tuple, dict] = {}

SPSDK_SECRETS_PATH = os.environ.get(
    "SPSDK_SECRETS_PATH", os.path.expanduser("~/.spsdk/secrets.yaml")
)


class Endianness(str, Enum):
    """Endianness enum."""

    BIG = "big"
    LITTLE = "little"

    @classmethod
    def values(cls) -> List[str]:
        """Get enumeration values."""
        return [mem.value for mem in Endianness.__members__.values()]


class BinaryPattern:
    """Binary pattern class.

    Supported patterns:
        - rand: Random Pattern
        - zeros: Filled with zeros
        - ones: Filled with all ones
        - inc: Filled with repeated numbers incremented by one 0-0xff
        - any kind of number, that will be repeated to fill up whole image.
          The format could be decimal, hexadecimal, bytes.
    """

    SPECIAL_PATTERNS = ["rand", "zeros", "ones", "inc"]

    def __init__(self, pattern: str) -> None:
        """Constructor of pattern class.

        :param pattern: Supported patterns:
                        - rand: Random Pattern
                        - zeros: Filled with zeros
                        - ones: Filled with all ones
                        - inc: Filled with repeated numbers incremented by one 0-0xff
                        - any kind of number, that will be repeated to fill up whole image.
                        The format could be decimal, hexadecimal, bytes.
        :raises SPSDKValueError: Unsupported pattern detected.
        """
        try:
            value_to_int(pattern)
        except SPSDKError as e:
            if pattern not in BinaryPattern.SPECIAL_PATTERNS:
                raise SPSDKValueError(  # pylint: disable=raise-missing-from
                    f"Unsupported input pattern {pattern}"
                ) from e

        self._pattern = pattern

    def get_block(self, size: int) -> bytes:
        """Get block filled with pattern.

        :param size: Size of block to return.
        :return: Filled up block with specified pattern.
        """
        if self._pattern == "zeros":
            return bytes(size)

        if self._pattern == "ones":
            return bytes(b"\xff" * size)

        if self._pattern == "rand":
            return token_bytes(size)

        if self._pattern == "inc":
            return bytes((x & 0xFF for x in range(size)))

        pattern = value_to_bytes(self._pattern, align_to_2n=False)
        block = bytes(pattern * (int((size / len(pattern))) + 1))
        return block[:size]

    @property
    def pattern(self) -> str:
        """Get the pattern.

        :return: Pattern in string representation.
        """
        try:
            return hex(value_to_int(self._pattern))
        except SPSDKError:
            return self._pattern


def align(number: int, alignment: int = 4) -> int:
    """Align number (size or address) size to specified alignment, typically 4, 8 or 16 bytes boundary.

    :param number: input to be aligned
    :param alignment: the boundary to align; typical value is power of 2
    :return: aligned number; result is always >= size (e.g. aligned up)
    :raises SPSDKError: When there is wrong alignment
    """
    if alignment <= 0 or number < 0:
        raise SPSDKError("Wrong alignment")

    return (number + (alignment - 1)) // alignment * alignment


def align_block(
    data: Union[bytes, bytearray],
    alignment: int = 4,
    padding: Optional[Union[int, str, BinaryPattern]] = None,
) -> bytes:
    """Align binary data block length to specified boundary by adding padding bytes to the end.

    :param data: to be aligned
    :param alignment: boundary alignment (typically 2, 4, 16, 64 or 256 boundary)
    :param padding: byte to be added or BinaryPattern
    :return: aligned block
    :raises SPSDKError: When there is wrong alignment
    """
    assert isinstance(data, (bytes, bytearray))

    if alignment < 0:
        raise SPSDKError("Wrong alignment")
    current_size = len(data)
    num_padding = align(current_size, alignment) - current_size
    if not num_padding:
        return bytes(data)
    if not padding:
        padding = BinaryPattern("zeros")
    elif not isinstance(padding, BinaryPattern):
        padding = BinaryPattern(str(padding))
    return bytes(data + padding.get_block(num_padding))


def align_block_fill_random(data: bytes, alignment: int = 4) -> bytes:
    """Same as `align_block`, just parameter `padding` is fixed to `-1` to fill with random data."""
    return align_block(data, alignment, BinaryPattern("rand"))


def get_bytes_cnt_of_int(
    value: int, align_to_2n: bool = True, byte_cnt: Optional[int] = None
) -> int:
    """Returns count of bytes needed to store handled integer.

    :param value: Input integer value.
    :param align_to_2n: The result will be aligned to standard sizes 1,2,4,8,12,16,20.
    :param byte_cnt: The result count of bytes.
    :raises SPSDKValueError: The integer input value doesn't fit into byte_cnt.
    :return: Number of bytes needed to store integer.
    """
    cnt = 0
    if value == 0:
        return byte_cnt or 1

    while value != 0:
        value >>= 8
        cnt += 1

    if align_to_2n and cnt > 2:
        cnt = int(ceil(cnt / 4)) * 4

    if byte_cnt and cnt > byte_cnt:
        raise SPSDKValueError(
            f"Value takes more bytes than required byte count {byte_cnt} after align."
        )

    cnt = byte_cnt or cnt

    return cnt


def value_to_int(value: Union[bytes, bytearray, int, str], default: Optional[int] = None) -> int:
    """Function loads value from lot of formats to integer.

    :param value: Input value.
    :param default: Default Value in case of invalid input.
    :return: Value in Integer.
    :raises SPSDKError: Unsupported input type.
    """
    if isinstance(value, int):
        return value

    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, Endianness.BIG.value)

    if isinstance(value, str) and value != "":
        match = re.match(
            r"(?P<prefix>0[box])?(?P<number>[0-9a-f_]+)(?P<suffix>[ul]{0,3})$",
            value.strip().lower(),
        )
        if match:
            base = {"0b": 2, "0o": 8, "0": 10, "0x": 16, None: 10}[match.group("prefix")]
            try:
                return int(match.group("number"), base=base)
            except ValueError:
                pass

    if default is not None:
        return default
    raise SPSDKError(f"Invalid input number type({type(value)}) with value ({value})")


def value_to_bytes(
    value: Union[bytes, bytearray, int, str],
    align_to_2n: bool = True,
    byte_cnt: Optional[int] = None,
    endianness: Endianness = Endianness.BIG,
) -> bytes:
    """Function loads value from lot of formats.

    :param value: Input value.
    :param align_to_2n: When is set, the function aligns length of return array to 1,2,4,8,12 etc.
    :param byte_cnt: The result count of bytes.
    :param endianness: The result bytes endianness ['big', 'little'].
    :return: Value in bytes.
    """
    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    value = value_to_int(value)
    return value.to_bytes(
        get_bytes_cnt_of_int(value, align_to_2n, byte_cnt=byte_cnt), endianness.value
    )


def size_fmt(num: Union[float, int], use_kibibyte: bool = True) -> str:
    """Size format."""
    base, suffix = [(1000.0, "B"), (1024.0, "iB")][use_kibibyte]
    i = "B"
    for i in ["B"] + [i + suffix for i in list("kMGTP")]:  # noqa: B007
        if num < base:
            break
        num /= base

    return f"{int(num)} {i}" if i == "B" else f"{num:3.1f} {i}"


def swap16(x: int) -> int:
    """Swap bytes in half word (16bit).

    :param x: Original number
    :return: Number with swapped bytes
    :raises SPSDKError: When incorrect number to be swapped is provided
    """
    if x < 0 or x > 0xFFFF:
        raise SPSDKError("Incorrect number to be swapped")
    return ((x << 8) & 0xFF00) | ((x >> 8) & 0x00FF)


def find_file(
    file_path: str,
    use_cwd: bool = True,
    search_paths: Optional[list[str]] = None,
    raise_exc: bool = True,
) -> str:
    """Find file in filesystem using multiple search strategies.

    The method searches for a file by checking the provided path directly, then optionally
    searching in the current working directory and additional search paths. Search paths
    take precedence over current working directory when both are enabled.

    :param file_path: File name, part of file path or full path to search for.
    :param use_cwd: Try current working directory to find the file, defaults to True.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :param raise_exc: Raise exception if file is not found, defaults to True.
    :return: Full absolute path to the found file.
    :raises SPSDKError: File not found in any of the search locations.
    """
    return _find_path(
        path=file_path,
        check_func=os.path.isfile,
        use_cwd=use_cwd,
        search_paths=search_paths,
        raise_exc=raise_exc,
    )


def load_hex_string(
    source: Optional[Union[str, int, bytes]],
    expected_size: int,
    search_paths: Optional[list[str]] = None,
    name: Optional[str] = "key",
) -> bytes:
    """Load hexadecimal data from various sources.

    The method supports loading from file paths, direct hexadecimal strings, bytes, or integers.
    If no source is provided, a random value of the expected size is generated. The method
    handles both text files containing hex strings and binary files.

    :param source: File path, hexadecimal string, bytes, or integer. Random value if None.
    :param expected_size: Expected size of the data in bytes.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :param name: Name for the key/data to load, defaults to "key".
    :raises SPSDKError: Invalid input data or size mismatch.
    :return: Data in bytes with the expected size.
    """
    assert source

    key = None
    if expected_size < 1:
        raise SPSDKError(f"Expected size of key must be positive. Got: {expected_size}")

    if isinstance(source, (bytes, int)):
        return value_to_bytes(source, byte_cnt=expected_size)

    try:
        file_path = find_file(source, search_paths=search_paths)
        try:
            str_key = load_file(file_path)
            assert isinstance(str_key, str)
            if not str_key.startswith(("0x", "0X")):
                str_key = "0x" + str_key
            key = value_to_bytes(str_key, byte_cnt=expected_size)
            if len(key) != expected_size:
                raise SPSDKError(f"Invalid {name} size. Expected: {expected_size}, got: {len(key)}")
        except (SPSDKError, UnicodeDecodeError):
            key = load_binary(file_path)
    except Exception:
        try:
            if not source.startswith(("0x", "0X")):
                source = "0x" + source
            key = value_to_bytes(source, byte_cnt=expected_size)
        except SPSDKError:
            pass

    if key is None:
        raise SPSDKError(f"Invalid key input: {source}")
    if len(key) != expected_size:
        raise SPSDKError(f"Invalid {name} size. Expected: {expected_size}, got: {len(key)}")

    return key


def load_text(path: str, search_paths: Optional[list[str]] = None) -> str:
    """Load text file content into string.

    The method loads a text file and returns its content as a string. It supports
    searching for the file in multiple directories if search paths are provided.

    :param path: Path to the text file to load.
    :param search_paths: List of directories to search for the file, defaults to None.
    :return: Content of the text file as string.
    """
    text = load_file(path, mode="r", search_paths=search_paths)
    assert isinstance(text, str)
    return text


def load_file(
    path: str, mode: str = "r", search_paths: Optional[list[str]] = None
) -> Union[str, bytes]:
    """Load file content from specified path.

    The method searches for the file in provided search paths and loads its content
    either as text or binary data based on the specified mode.

    :param path: Path to the file to be loaded.
    :param mode: File reading mode, 'r' for text or 'rb' for binary.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :return: File content as string (text mode) or bytes (binary mode).
    """
    path = find_file(path, search_paths=search_paths)
    text_file = bool("b" not in mode)
    encoding = "utf-8" if text_file else None
    try:
        with open(path, mode, encoding=encoding) as f:
            return f.read()
    except UnicodeDecodeError as exc:
        raise SPSDKError(f"Failed to load file {path}") from exc


def write_file(
    data: Union[str, bytes, bytearray],
    path: str,
    mode: str = "w",
    encoding: str = "utf-8",
    overwrite: bool = True,
) -> int:
    """Write data to a file with automatic directory creation and overwrite protection.

    The method automatically creates parent directories if they don't exist and supports
    both text and binary modes. When overwrite is disabled, it generates a unique filename
    by appending a counter to avoid conflicts.

    :param data: Data to write to the file.
    :param path: Path to the target file.
    :param mode: File writing mode ('w' for text, 'wb' for binary), defaults to 'w'.
    :param encoding: Text encoding ('ascii', 'utf-8'), defaults to 'utf-8'.
    :param overwrite: Whether to overwrite existing files, defaults to True.
    :return: Number of characters or bytes written to the file.
    """
    path = path.replace("\\", "/")
    folder = os.path.dirname(path)
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)

    # If overwrite is False and file exists, modify path by appending number
    if not overwrite and os.path.exists(path):
        base_path, ext = os.path.splitext(path)
        counter = 1
        new_path = f"{base_path}_{counter}{ext}"
        while os.path.exists(new_path):
            counter += 1
            new_path = f"{base_path}_{counter}{ext}"
        path = new_path

    with open(path, mode, encoding=None if "b" in mode else encoding) as f:
        return f.write(data)


def load_binary(path: str, search_paths: Optional[list[str]] = None) -> bytes:
    """Load binary file into bytes.

    The method loads a binary file from the specified path or searches for it
    in the provided search paths if the direct path doesn't exist.

    :param path: Path to the binary file to load.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :return: Content of the binary file as bytes.
    """
    data = load_file(path, mode="rb", search_paths=search_paths)
    assert isinstance(data, bytes)
    return data


def get_abs_path(file_path: str, base_dir: Optional[str] = None) -> str:
    """Convert relative or absolute file path to normalized absolute path.

    The method handles both relative and absolute paths, normalizing path separators
    to forward slashes for cross-platform compatibility.

    :param file_path: File path to be converted to absolute path.
    :param base_dir: Base directory to create absolute path, if not specified the system CWD is used.
    :return: Absolute file path with normalized separators.
    """
    if os.path.isabs(file_path):
        return file_path.replace("\\", "/")

    return os.path.abspath(os.path.join(base_dir or os.getcwd(), file_path)).replace("\\", "/")


def _find_path(
    path: str,
    check_func: Callable[[str], bool],
    use_cwd: bool = True,
    search_paths: Optional[list[str]] = None,
    raise_exc: bool = True,
) -> str:
    """Find and return the full path to a file or directory.

    The method searches for the given path in multiple locations with configurable search order.
    Search paths take precedence over current working directory when both are specified.

    :param path: File name, part of file path or full path to search for.
    :param check_func: Function to validate if the found path exists and meets criteria.
    :param use_cwd: Try current working directory to find the file, defaults to True.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :param raise_exc: Raise exception if file is not found, defaults to True.
    :return: Full absolute path to the found file or empty string if not found and raise_exc is False.
    :raises SPSDKError: File not found in any of the searched locations.
    """
    path = path.replace("\\", "/")

    if os.path.isabs(path):
        if not check_func(path):
            if raise_exc:
                raise SPSDKError(f"Path '{path}' not found")
            return ""
        return path
    if search_paths:
        for dir_candidate in search_paths:
            if not dir_candidate:
                continue
            dir_candidate = dir_candidate.replace("\\", "/")
            path_candidate = get_abs_path(path, base_dir=dir_candidate)
            if check_func(path_candidate):
                return path_candidate
    if use_cwd and check_func(path):
        return get_abs_path(path)
    # list all directories in error message
    searched_in: list[str] = []
    if use_cwd:
        searched_in.append(os.path.abspath(os.curdir))
    if search_paths:
        searched_in.extend(filter(None, search_paths))
    searched_in = [s.replace("\\", "/") for s in searched_in]
    err_str = f"Path '{path}' not found, Searched in: {', '.join(searched_in)}"
    if not raise_exc:
        return ""
    raise SPSDKError(err_str)


def parse_bd_config(content: str) -> dict[str, Any]:
    """Simple BD config parser without sly dependency.

    Parses options, sources, and section blocks from BD format.
    """

    config: dict[str, Any] = {}

    # Parse options block
    options_match = re.search(r"options\s*\{([^}]+)\}", content, re.DOTALL)
    if options_match:
        options: dict[str, Any] = {}
        for pair in re.finditer(r"(\w+)\s*=\s*([^;]+);", options_match.group(1)):
            key, value = pair.groups()
            value = value.strip()
            # Parse different value types
            if value.startswith('"') and value.endswith('"'):
                options[key] = value[1:-1]  # string
            elif value.startswith("0x"):
                options[key] = int(value, 16)  # hex
            elif value.isdigit():
                options[key] = int(value)  # int
            else:
                options[key] = value
        config["options"] = options

    # Parse sources block
    sources_match = re.search(r"sources\s*\{([^}]+)\}", content, re.DOTALL)
    if sources_match:
        sources: dict[str, Any] = {}
        for pair in re.finditer(r"(\w+)\s*=\s*([^;]+);", sources_match.group(1)):
            key, value = pair.groups()
            sources[key] = value.strip()
        config["sources"] = sources

    # Parse sections
    sections = []
    for section_match in re.finditer(r"section\s*\((\d+)\)\s*\{([^}]+)\}", content, re.DOTALL):
        section_num = int(section_match.group(1))
        section_body = section_match.group(2)
        commands = [cmd.strip() for cmd in section_body.split(";") if cmd.strip()]
        sections.append({"number": section_num, "commands": commands})

    if sections:
        config["sections"] = sections

    return config


def value_to_bool(value: Optional[Union[bool, int, str]]) -> bool:
    """Convert various input formats to boolean value.

    The function accepts boolean, integer, string, or None values and converts them
    to boolean. For strings, it recognizes "True", "true", "T", and "1" as True,
    all other strings as False. For other types, uses Python's built-in bool() conversion.

    :param value: Input value to convert (bool, int, str, or None).
    :return: Boolean representation of the input value.
    :raises SPSDKError: Unsupported input type.
    """
    if isinstance(value, str):
        return value in ("True", "true", "T", "1")

    return bool(value)
