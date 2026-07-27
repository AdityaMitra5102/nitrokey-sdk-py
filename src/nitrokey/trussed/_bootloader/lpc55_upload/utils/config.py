#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK configuration management utilities.

This module provides a unified configuration framework for SPSDK applications,
including configuration validation, preprocessing hooks, and type-safe configuration
handling across the NXP MCU portfolio.
"""

import logging
import os
from typing import Any, Callable, Optional, TypeVar, Union

from spsdk.utils.schema_validator import check_config

from .commands import CmdBaseClass
from .exceptions import SPSDKError, SPSDKKeyError
from .misc import value_to_bytes, value_to_int

logger = logging.getLogger(__name__)
_VT = TypeVar("_VT")


class Config(dict):
    """SPSDK Configuration Manager.

    This class extends Python's dictionary to provide enhanced configuration management
    for SPSDK operations. It supports nested key addressing using path separators,
    file-based configuration loading, and maintains context about configuration
    source and search paths.

    :cvar SEP: Path separator used for nested key addressing in configuration.
    """

    SEP = "/"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize configuration dictionary with default settings.

        Sets up a new configuration dictionary instance with default values for
        configuration directory (current working directory), empty configuration name,
        and empty search paths list.

        :param args: Variable length argument list passed to parent dictionary constructor.
        :param kwargs: Arbitrary keyword arguments passed to parent dictionary constructor.
        """
        super().__init__(*args, **kwargs)
        self.config_dir = os.getcwd()
        self.config_name = ""
        self.search_paths: list[str] = []

    @classmethod
    def get_path(cls, key: Union[str, int]) -> list:
        """Get keypath in list format.

        Converts a key (string or integer) into a list of path components. String keys are split
        by the separator and each component is converted to integer if possible, otherwise kept
        as string.

        :param key: Key to convert - either string path with separators or single integer.
        :return: List of path components as integers or strings.
        """
        ret: list[Union[int, str]] = []

        if isinstance(key, int):
            return [str(key)]
        for k in key.split(cls.SEP):
            try:
                ret.append(value_to_int(k))
            except SPSDKError:
                ret.append(k)
        return ret

    def get(self, key: str, defaults: Optional[Any] = None) -> Any:
        """Get configuration value with nested key support.

        Overrides the original dictionary get method to support nested addressing of items
        using '/' as a path separator.

        :param key: Key name including support of key path with '/'.
        :param defaults: Default value in case that item doesn't exist, defaults to None.
        :return: Configuration value or default if key not found.
        """
        try:
            return self.__getitem__(key)
        except SPSDKError:
            return defaults

    def __getitem__(self, key: str) -> Any:
        """Get configuration value by key path.

        Retrieves a value from the configuration using a dot-separated key path or a simple key.
        The method supports nested access to dictionaries and lists within the configuration.

        :param key: Configuration key or dot-separated path to nested value
        :raises SPSDKError: Invalid key path or unsupported data type in path
        :raises SPSDKKeyError: Key doesn't exist in configuration
        :return: Configuration value at the specified key path
        """

        def gets(source: Any, key_path: list) -> Any:
            """Get value from nested data structure using key path.

            Retrieves a value from a nested dictionary or list structure by following
            a sequence of keys. Supports both dictionary keys and list indices.

            :param source: The data structure to search in (dict or list).
            :param key_path: List of keys/indices defining the path to the desired value.
            :raises SPSDKError: Invalid key type for list access or unsupported source type.
            :raises SPSDKKeyError: Key doesn't exist in the data structure.
            :return: The value found at the specified key path.
            """
            key = key_path.pop(0)
            if isinstance(source, list):
                if not isinstance(key, int):
                    raise SPSDKError("Invalid key path - from list must be used number as key")
                ret = source[key]
            elif isinstance(source, dict):
                ret = dict.get(source, key)
            else:
                raise SPSDKError("Invalid configuration key path.")

            if ret is None:
                raise SPSDKKeyError(f"The {key} doesn't exists in {str(self)}")

            if len(key_path):
                return gets(ret, key_path)

            return ret

        try:
            return gets(self, self.get_path(key))
        except SPSDKKeyError:
            return gets(self, [key])

    def __setitem__(self, key: str, value: Any) -> None:
        """Set configuration value using dot-notation key path.

        This method allows setting nested configuration values using a dot-separated key path.
        It automatically creates intermediate dictionaries or lists as needed based on the
        key types in the path.

        :param key: Dot-separated key path (e.g., 'section.subsection.item').
        :param value: Value to set at the specified key path.
        :raises SPSDKError: Invalid configuration key path.
        """

        def sets(dest: Any, key_path: list, value: Any) -> None:
            """Set value in nested data structure using key path.

            Recursively traverses and modifies a nested data structure (dict/list) by following
            a key path. Creates intermediate containers as needed during traversal.

            :param dest: Target data structure to modify (dict or list).
            :param key_path: List of keys defining the path to the target location.
            :param value: Value to set at the target location.
            :raises SPSDKError: Invalid key type in configuration key path.
            """
            key = key_path.pop(0)

            if isinstance(key, int):
                if len(key_path) == 0:
                    dest[key] = value
                    return
                if key > len(dest):
                    dest[key] = []
                sets(dest[key], key_path, value)
            elif isinstance(key, str):
                if len(key_path) == 0:
                    dict.__setitem__(dest, key, value)
                    return
                if key not in dest:
                    dest[key] = {}
                sets(dest[key], key_path, value)
            else:
                raise SPSDKError("Invalid configuration key path.")

        sets(self, self.get_path(key), value)

    def get_output_file_name(self, key: str) -> str:
        """Get the absolute output file name.

        Resolves relative paths by joining them with the configuration directory path and converts
        the result to use forward slashes for consistency across platforms.

        :param key: Key path to config with output file name.
        :return: The absolute path to output file with forward slashes.
        """
        path = self[key]
        if os.path.isabs(path):
            return path
        return str(os.path.abspath(os.path.join(self.config_dir, path))).replace("\\", "/")

    def get_output_dir(self, key: str) -> str:
        """Get the absolute output directory.

        :param key: Key path to config with output directory.
        :return: The absolute path to output directory.
        """
        output_file_name = self.get_output_file_name(key)
        return os.path.dirname(output_file_name)

    def get_list_of_configs(
        self, key: str, default: Optional[list["Config"]] = None
    ) -> list["Config"]:
        """Get list of sub configurations.

        The method retrieves a list of sub-configuration objects from the specified key.
        If the key doesn't exist and no default is provided, raises an exception.

        :param key: Key name of the list of sub configuration.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: When the key is not found and no default value is provided.
        :return: List of sub configuration objects.
        """
        if key not in self:
            if default is not None:
                return default
            raise SPSDKError(f"The value is not in config at key: {key}")

        ret = []
        for i in range(len(self[key])):
            ret.append(self.get_config(f"{key}/{i}"))
        return ret

    def get_config(self, key: str, default: Optional["Config"] = None) -> "Config":
        """Get the key value as Config object.

        Retrieves a configuration value by key and converts it to a Config instance.
        The returned Config object inherits search paths and config directory from the parent.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKKeyError: The key is not found in configuration and no default provided.
        :return: Sub configuration as Config object.
        """
        cfg = self.get(key, default)
        if cfg is None:
            raise SPSDKKeyError(f"The value is not in config at key: {key}")
        ret = Config(cfg)
        ret.search_paths = self.search_paths
        ret.config_dir = self.config_dir

        return ret

    def get_dict(self, key: str, default: Optional[dict] = None) -> dict:
        """Get the key value as dictionary.

        Retrieves a configuration value for the specified key and ensures it is a dictionary type.
        If the value exists but is not a dictionary, an exception is raised.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: If the retrieved value is not a dictionary type.
        :return: Sub configuration as dictionary.
        """
        ret = self.get(key, default)
        if not isinstance(ret, dict):
            raise SPSDKError(f"The value is not dictionary at key: {key}")
        return ret

    def get_list(self, key: str, default: Optional[list] = None) -> list:
        """Get the key value as list.

        :param key: Key name of the configuration entry.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: If the value at the specified key is not a list.
        :return: Configuration value as list.
        """
        ret = self.get(key, default)
        if not isinstance(ret, list):
            raise SPSDKError(f"The value is not list at key: {key}")
        return ret

    def get_int(self, key: str, default: Optional[int] = None) -> int:
        """Get the key value as integer.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contain it.
        :raises SPSDKError: The value is not integer at specified key.
        :return: Integer loaded from configuration.
        """
        ret = self.get(key, default)
        if ret is None:
            raise SPSDKError(f"The value is not integer at key: {key}")
        return value_to_int(ret)

    def get_bytes(self, key: str, default: Optional[bytes] = None) -> bytes:
        """Get the key value as bytes.

        The method retrieves a configuration value by key and converts it to bytes format.
        If the key is not found and no default is provided, an exception is raised.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: When the value cannot be converted to bytes or key is missing without default.
        :return: Bytes array loaded from configuration.
        """
        ret = self.get(key, default)
        if ret is None:
            raise SPSDKError(f"The value is not bytes at key: {key}")
        return value_to_bytes(ret, align_to_2n=False)

    def get_str(self, key: str, default: Optional[str] = None) -> str:
        """Get the key value as string.

        Retrieves the configuration value for the specified key and ensures it's a string type.
        If the value exists but is not a string, an exception is raised.

        :param key: Key name of the configuration entry.
        :param default: Default value to return if the key doesn't exist in configuration.
        :raises SPSDKError: If the retrieved value is not a string type.
        :return: Configuration value as string.
        """
        ret = self.get(key, default)
        if not isinstance(ret, str):
            raise SPSDKError(f"The value is not string at key: {key}")
        return ret

    def get_bool(self, key: str, default: Optional[bool] = None) -> bool:
        """Get the key value as boolean.

        Retrieves a configuration value for the specified key and ensures it is a boolean type.
        If the key is not found, returns the provided default value.

        :param key: Key name of the configuration entry.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: If the retrieved value is not a boolean type.
        :return: Boolean value from configuration.
        """
        ret = self.get(key, default)
        if not isinstance(ret, bool):
            raise SPSDKError(f"The value is not boolean at key: {key}")
        return ret

    def check(self, schemas: list[dict[str, Any]], check_unknown_props: bool = False) -> None:
        """Check configuration against validation schemas.

        The method validates the current configuration object against provided schemas
        and optionally checks for unknown properties that might indicate configuration
        errors.

        :param schemas: List of validation schemas used in SPSDK.
        :param check_unknown_props: If True, check for unknown properties in config
            and print warnings.
        """
        check_config(
            self, schemas, search_paths=self.search_paths, check_unknown_props=check_unknown_props
        )


class SB21Helper:
    """SB21 Helper for Secure Binary 2.1 command processing.

    This class provides utilities for processing and converting Boot Descriptor (BD) file
    commands into corresponding SB2.1 command objects. It manages command mapping,
    memory ID resolution, and handles various secure boot operations including
    loading, encryption, key management, and memory operations.
    """

    def __init__(
        self, search_paths: Optional[list[str]] = None, zero_filling: bool = False
    ) -> None:
        """Initialize SB21 helper for processing secure boot commands.

        The helper manages command execution with configurable search paths for data files
        and optional zero filling for memory operations.

        :param search_paths: List of paths to search for data files, defaults to None
        :param zero_filling: Enable zero filling for memory operations, defaults to False
        """
        self.search_paths = search_paths
        self.cmds = {
            "load": self._load,
            "fill": self._fill_memory,
            "erase": self._erase_cmd_handler,
            "enable": self._enable,
            "encrypt": self._encrypt,
            "keywrap": self._keywrap,
            "keystore_to_nv": self._keystore_to_nv,
            "keystore_from_nv": self._keystore_from_nv,
            "version_check": self._version_check,
            "jump": self._jump,
            "programFuses": self._prog,
        }
        self.zero_filling = zero_filling

    def get_command(self, cmd_name: str) -> Callable[[dict], CmdBaseClass]:
        """Get command factory function by name.

        Retrieves a callable function that creates command objects based on the provided
        command name. The command names correspond to those used in JSON files generated
        by the bd file parser (load, fill, erase, etc.).

        :param cmd_name: Command name identifier. Valid values are 'load', 'fill',
            'erase', 'enable', 'reset', 'encrypt', 'keywrap'.
        :return: Callable function that takes a dictionary and returns a command object.
        """
        command_object = self.cmds[cmd_name]
        return command_object
