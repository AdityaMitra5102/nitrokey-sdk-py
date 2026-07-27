#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Boot Image V2.0, V2.1."""

import os
from datetime import datetime
from typing import Any, Iterator, List, Optional

from typing_extensions import Self

from nitrokey.trussed._bootloader.nrf52_upload.dfu.signing import Signing

from ...crypto.certificate import Certificate
from ...crypto.hash import EnumHashAlgorithm, get_hash
from ...crypto.hmac import hmac_sha256 as hmac
from ...crypto.keys import ECDSASignature
from ...crypto.symmetric import Counter, aes_key_unwrap, aes_key_wrap
from ...crypto.types import SPSDKEncoding
from ...exceptions import SPSDKError
from ...sbfile.misc import SecBootBlckSize
from ...utils.abstract import BaseClass
from ...utils.config import Config, SB21Helper
from ...utils.crypto.cert_blocks import CertBlockV1
from ...utils.misc import (
    load_hex_string,
    load_text,
    parse_bd_config,
    value_to_bytes,
    value_to_int,
    write_file,
)
from .commands import CmdHeader
from .headers import ImageHeaderV2
from .sections import BootSectionV2


class SBV2xAdvancedParams:
    """The class holds advanced parameters for the SB file encryption.

    These parameters are used for the tests; for production, use can use default values (random keys + current time)
    """

    def __init__(self, dek: bytes, mac: bytes, nonce: bytes, timestamp: datetime) -> None:
        """Initialize SBV2xAdvancedParams.

        :param dek: DEK key
        :param mac: MAC key
        :param nonce: nonce
        :param timestamp: fixed timestamp for the header; use None to use current date/time
        :raises SPSDKError: Invalid dek or mac
        :raises SPSDKError: Invalid length of nonce
        """
        self._dek = dek
        self._mac = mac
        self._nonce = nonce
        self._timestamp = datetime.fromtimestamp(int(timestamp.timestamp()))
        if len(self._dek) != 32 and len(self._mac) != 32:
            raise SPSDKError("Invalid dek or mac")
        if len(self._nonce) != 16:
            raise SPSDKError("Invalid length of nonce")

    @property
    def dek(self) -> bytes:
        """Return DEK key."""
        return self._dek

    @property
    def mac(self) -> bytes:
        """Return MAC key."""
        return self._mac

    @property
    def nonce(self) -> bytes:
        """Return NONCE."""
        return self._nonce

    @property
    def timestamp(self) -> datetime:
        """Return timestamp."""
        return self._timestamp


########################################################################################################################
# Secure Boot Image Class (Version 2.1)
########################################################################################################################
class BootImageV21(BaseClass):
    """Boot Image V2.1 class."""

    # Image specific data
    HEADER_MAC_SIZE = 32
    KEY_BLOB_SIZE = 80
    SHA_256_SIZE = 32

    # defines
    FLAGS_SHA_PRESENT_BIT = 0x8000  # image contains SHA-256
    FLAGS_ENCRYPTED_SIGNED_BIT = 0x0008  # image is signed and encrypted

    def __init__(
        self,
        kek: bytes,
        *sections: BootSectionV2,
        product_version: str,
        component_version: str,
        build_number: int,
        advanced_params: SBV2xAdvancedParams,
        flags: int = FLAGS_SHA_PRESENT_BIT | FLAGS_ENCRYPTED_SIGNED_BIT,
    ) -> None:
        """Initialize Secure Boot Image V2.1.

        :param kek: key to wrap DEC and MAC keys

        :param product_version: The product version (default: 1.0.0)
        :param component_version: The component version (default: 1.0.0)
        :param build_number: The build number value (default: 0)

        :param advanced_params: optional advanced parameters for encryption; it is recommended to use default value
        :param flags: see flags defined in class.
        :param sections: Boot sections
        """
        self._kek = kek
        self._dek = advanced_params.dek
        self._mac = advanced_params.mac
        self._header = ImageHeaderV2(
            version="2.1",
            product_version=product_version,
            component_version=component_version,
            build_number=build_number,
            flags=flags,
            nonce=advanced_params.nonce,
            timestamp=advanced_params.timestamp,
        )
        self._cert_block: Optional[CertBlockV1] = None
        self.boot_sections: List[BootSectionV2] = []
        # ...
        for section in sections:
            self.add_boot_section(section)

    @property
    def header(self) -> ImageHeaderV2:
        """Return image header."""
        return self._header

    @property
    def dek(self) -> bytes:
        """Data encryption key."""
        return self._dek

    @property
    def mac(self) -> bytes:
        """Message authentication code."""
        return self._mac

    @property
    def kek(self) -> bytes:
        """Return key to wrap DEC and MAC keys."""
        return self._kek

    @property
    def cert_block(self) -> Optional[CertBlockV1]:
        """Return certificate block; None if SB file not signed or block not assigned yet."""
        return self._cert_block

    @cert_block.setter
    def cert_block(self, value: CertBlockV1) -> None:
        """Setter.

        :param value: block to be assigned; None to remove previously assigned block
        """
        assert isinstance(value, CertBlockV1)
        self._cert_block = value
        self._cert_block.alignment = 16

    @property
    def signed(self) -> bool:
        """Return flag whether SB file is signed."""
        return True  # SB2.1 is always signed

    @property
    def cert_header_size(self) -> int:
        """Return image raw size (not aligned) for certificate header."""
        size = ImageHeaderV2.SIZE + self.HEADER_MAC_SIZE
        size += self.KEY_BLOB_SIZE
        # Certificates Section
        cert_blk = self.cert_block
        if cert_blk:
            size += cert_blk.raw_size
        return size

    @property
    def raw_size(self) -> int:
        """Return image raw size (not aligned)."""
        # Header, HMAC and KeyBlob
        size = ImageHeaderV2.SIZE + self.HEADER_MAC_SIZE
        size += self.KEY_BLOB_SIZE
        # Certificates Section
        cert_blk = self.cert_block
        if cert_blk:
            size += cert_blk.raw_size
            if not self.signed:  # pragma: no cover # SB2.1 is always signed
                raise SPSDKError("Certificate block is not signed")
            size += cert_blk.signature_size
        # Boot Sections
        for boot_section in self.boot_sections:
            size += boot_section.raw_size
        return size

    def __len__(self) -> int:
        return len(self.boot_sections)

    def __getitem__(self, key: int) -> BootSectionV2:
        return self.boot_sections[key]

    def __setitem__(self, key: int, value: BootSectionV2) -> None:
        self.boot_sections[key] = value

    def __iter__(self) -> Iterator[BootSectionV2]:
        return self.boot_sections.__iter__()

    def update(self) -> None:
        """Update BootImageV21."""
        if self.boot_sections:
            self._header.first_boot_section_id = self.boot_sections[0].uid
            # calculate first boot tag block
            data_size = self._header.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
            cert_blk = self.cert_block
            if cert_blk is not None:
                data_size += cert_blk.raw_size
                if not self.signed:  # pragma: no cover # SB2.1 is always signed
                    raise SPSDKError("Certificate block is not signed")
                data_size += cert_blk.signature_size
            self._header.first_boot_tag_block = SecBootBlckSize.to_num_blocks(data_size)
        # ...
        self._header.image_blocks = SecBootBlckSize.to_num_blocks(self.raw_size)
        self._header.header_blocks = SecBootBlckSize.to_num_blocks(self._header.SIZE)
        self._header.offset_to_certificate_block = (
            self._header.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
        )
        # Get HMAC count
        self._header.max_section_mac_count = 0
        for boot_sect in self.boot_sections:
            boot_sect.is_last = True  # unified with elftosb
            self._header.max_section_mac_count += boot_sect.hmac_count
        # Update certificates block header
        cert_clk = self.cert_block
        if cert_clk is not None:
            cert_clk.header.build_number = self._header.build_number
            cert_clk.header.image_length = self.cert_header_size

    def __repr__(self) -> str:
        return f"SB2.1, {'Signed' if self.signed else 'Plain'} "

    def __str__(self) -> str:
        """Return text description of the instance."""
        self.update()
        nfo = "\n"
        nfo += ":::::::::::::::::::::::::::::::::: IMAGE HEADER ::::::::::::::::::::::::::::::::::::::\n"
        nfo += str(self._header)
        if self.cert_block is not None:
            nfo += "::::::::::::::::::::::::::::::: CERTIFICATES BLOCK ::::::::::::::::::::::::::::::::::::\n"
            nfo += str(self.cert_block)
        nfo += "::::::::::::::::::::::::::::::::::: BOOT SECTIONS ::::::::::::::::::::::::::::::::::::\n"
        for index, section in enumerate(self.boot_sections):
            nfo += f"[ SECTION: {index} | UID: 0x{section.uid:08X} ]\n"
            nfo += str(section)
        return nfo

    def add_boot_section(self, section: BootSectionV2) -> None:
        """Add new Boot section into image.

        :param section: Boot section to be added
        :raises SPSDKError: Raised when section is not instance of BootSectionV2 class
        """
        if not isinstance(section, BootSectionV2):
            raise SPSDKError("Section is not instance of BootSectionV2 class")
        self.boot_sections.append(section)

    # pylint: disable=too-many-locals
    @classmethod
    def parse(
        cls, data: bytes, offset: int = 0, kek: bytes = bytes(), plain_sections: bool = False
    ) -> "BootImageV21":
        """Parse image from bytes.

        :param data: Raw data of parsed image
        :param offset: The offset of input data
        :param kek: The Key for unwrapping DEK and MAC keys (required)
        :param plain_sections: Sections are not encrypted; this is used only for debugging,
            not supported by ROM code
        :return: BootImageV21 parsed object
        :raises SPSDKError: raised when header is in incorrect format
        :raises SPSDKError: raised when signature is incorrect
        :raises SPSDKError: Raised when kek is empty
        :raises SPSDKError: raised when header's nonce not present"
        """
        if not kek:
            raise SPSDKError("kek cannot be empty")
        index = offset
        header_raw_data = data[index : index + ImageHeaderV2.SIZE]
        index += ImageHeaderV2.SIZE
        # Not used right now: hmac_data = data[index: index + cls.HEADER_MAC_SIZE]
        index += cls.HEADER_MAC_SIZE
        key_blob = data[index : index + cls.KEY_BLOB_SIZE]
        index += cls.KEY_BLOB_SIZE
        key_blob_unwrap = aes_key_unwrap(kek, key_blob[:-8])
        dek = key_blob_unwrap[:32]
        mac = key_blob_unwrap[32:]
        # Parse Header
        header = ImageHeaderV2.parse(header_raw_data)
        if header.offset_to_certificate_block != (index - offset):
            raise SPSDKError("Invalid offset")
        # Parse Certificate Block
        cert_block = CertBlockV1.parse(data[index:])
        index += cert_block.raw_size

        # Verify Signature
        signature_index = index
        # The image may contain SHA, in such a case the signature is placed
        # after SHA. Thus we must shift the index by SHA size.
        if header.flags & BootImageV21.FLAGS_SHA_PRESENT_BIT:
            signature_index += BootImageV21.SHA_256_SIZE
        result = cert_block.verify_data(
            data[signature_index : signature_index + cert_block.signature_size],
            data[offset:signature_index],
        )

        if not result:
            raise SPSDKError("Verification failed")
        # Check flags, if 0x8000 bit is set, the SB file contains SHA-256 between
        # certificate and signature.
        if header.flags & BootImageV21.FLAGS_SHA_PRESENT_BIT:
            bootable_section_sha256 = data[index : index + BootImageV21.SHA_256_SIZE]
            index += BootImageV21.SHA_256_SIZE
        index += cert_block.signature_size
        # Check first Boot Section HMAC
        # Not implemented yet
        # hmac_data_calc = hmac(mac, data[index + CmdHeader.SIZE: index + CmdHeader.SIZE + ((2) * 32)])
        # if hmac_data != hmac_data_calc:
        #    raise SPSDKError("HMAC failed")
        if not header.nonce:
            raise SPSDKError("Header's nonce not present")
        counter = Counter(header.nonce)
        counter.increment(SecBootBlckSize.to_num_blocks(index - offset))
        boot_section = BootSectionV2.parse(
            data, index, dek=dek, mac=mac, counter=counter, plain_sect=plain_sections
        )
        if header.flags & BootImageV21.FLAGS_SHA_PRESENT_BIT:
            computed_bootable_section_sha256 = get_hash(
                data[index:], algorithm=EnumHashAlgorithm.SHA256
            )

            if bootable_section_sha256 != computed_bootable_section_sha256:
                raise SPSDKError(
                    desc=(
                        "Error: invalid Bootable section SHA."
                        f"Expected {bootable_section_sha256.decode('utf-8')},"
                        f"got {computed_bootable_section_sha256.decode('utf-8')}"
                    )
                )
        adv_params = SBV2xAdvancedParams(
            dek=dek, mac=mac, nonce=header.nonce, timestamp=header.timestamp
        )
        obj = cls(
            kek=kek,
            product_version=str(header.product_version),
            component_version=str(header.component_version),
            build_number=header.build_number,
            advanced_params=adv_params,
        )
        obj.cert_block = cert_block
        obj.add_boot_section(boot_section)
        return obj

    @classmethod
    def parse_sb21_config(
        cls, config_path: str, external_files: Optional[list[str]] = None
    ) -> Config:
        """Parse SB2.1 configuration file and create configuration object.

        The method attempts to parse the configuration file as a BD (Boot Data) file first.
        If that fails, it falls back to parsing as a YAML configuration file with validation.

        :param config_path: Path to configuration file either BD or YAML formatted.
        :param external_files: Optional list of external files for BD processing.
        :raises SPSDKError: Invalid BD file or configuration parsing error.
        :raises SPSDKValueError: Missing required options or family key in BD file.
        :return: Parsed configuration object with family and revision information.
        """
        try:
            bd_file_content = load_text(config_path)
            parser = parse_bd_config(bd_file_content)
            parsed_conf = Config(parser)
            if parsed_conf is None:
                raise SPSDKError("Invalid bd file, secure binary file generation terminated")
            if "options" not in parsed_conf:
                raise SPSDKError("Missing 'options' block in BD file.")
            options: dict[str, Any] = parsed_conf["options"]
            if "family" not in options:
                raise SPSDKError("Missing 'family' key in BD file options block.")
            parsed_conf["family"] = options.pop("family")
            parsed_conf["revision"] = options.pop("revision", "latest")
            parsed_conf.config_dir = os.path.dirname(config_path)
            parsed_conf.search_paths = [parsed_conf.config_dir]
        except SPSDKError as exc:
            raise SPSDKError(f"Error in reading BD file {exc}") from exc

        return parsed_conf

    @classmethod
    def get_advanced_params(cls, config: dict[str, Any]) -> SBV2xAdvancedParams:
        """Get advanced parameters from configuration.

        Extracts and processes advanced SB 2.x parameters including timestamp, DEK, MAC,
        nonce, and zero padding settings from the provided configuration dictionary.

        :param config: Configuration dictionary containing advanced parameter settings.
        :return: Advanced parameters object for SB 2.x file generation.
        """
        # Test params
        timestamp = config.get("timestamp")
        if timestamp:  # re-format it
            timestamp = datetime.fromtimestamp(value_to_int(timestamp))
        else:
            timestamp = datetime.now()
        dek = config.get("dek")
        dek = value_to_bytes("0x" + dek, byte_cnt=32) if dek else b""
        mac = config.get("mac")
        mac = value_to_bytes("0x" + mac, byte_cnt=32) if mac else b""
        nonce = config.get("nonce")
        nonce = value_to_bytes("0x" + nonce, byte_cnt=16) if nonce else b""

        advanced_params = SBV2xAdvancedParams(dek, mac, nonce, timestamp)
        return advanced_params

    @classmethod
    def load_from_config(
        cls,
        config: Config,
        key_file_path: Optional[str] = None,
        signature_provider: Optional[Signing] = None,
        signing_certificate_file_paths: Optional[list[str]] = None,
        root_key_certificate_paths: Optional[list[str]] = None,
        rkth_out_path: Optional[str] = None,
    ) -> Self:
        """Create an instance of BootImageV21 from configuration.

        This method constructs a Secure Binary V2.1 image by parsing the provided configuration,
        setting up certificate blocks, loading encryption keys, processing sections and commands,
        and configuring signature providers. It also handles root key hash generation and output.

        :param config: Input standard configuration containing image settings and sections.
        :param key_file_path: Path to key file for SB-KEK encryption key.
        :param signature_provider: Signature provider instance to sign the final image.
        :param signing_certificate_file_paths: List of paths to signing certificate chain files.
        :param root_key_certificate_paths: List of paths to root key certificate files for
            verifying other certificates. Maximum 4 certificates allowed, extras ignored.
            One certificate must match the first in signing_certificate_file_paths.
        :param rkth_out_path: Output path for root key hash table file. If None, uses
            'hash.bin' in working directory or config-specified path.
        :return: Configured BootImageV21 instance ready for image generation.
        """
        options = config.get_config("options")
        flags = options.get_int(
            "flags", BootImageV21.FLAGS_SHA_PRESENT_BIT | BootImageV21.FLAGS_ENCRYPTED_SIGNED_BIT
        )

        product_version = options.get_str("productVersion", "1.0.0")
        component_version = options.get_str("componentVersion", "1.0.0")

        if signing_certificate_file_paths and root_key_certificate_paths:
            build_number = options.get_int("buildNumber", 1)
            cert_block = CertBlockV1(build_number=build_number)
            for cert_path in signing_certificate_file_paths:
                cert = Certificate.load(cert_path)
                cert_block.add_certificate(cert)
            for cert_idx, cert_path in enumerate(root_key_certificate_paths):
                cert = Certificate.load(cert_path)
                cert_block.set_root_key_hash(cert_idx, cert)

        if key_file_path:
            sb_kek = load_hex_string(key_file_path, expected_size=32)
        else:
            sb_kek = b"\xaa" * 32

        # validate keyblobs and perform appropriate actions
        keyblobs = config.get("keyblobs", [])

        # get advanced params
        advanced_params = cls.get_advanced_params(options)

        sb21_helper = SB21Helper(config.search_paths, zero_filling=advanced_params.zero_padding)
        sb_sections = []
        sections = config["sections"]
        for section_id, section in enumerate(sections):
            commands = []
            for cmd in section["commands"]:
                for key, value in cmd.items():
                    # we use a helper function, based on the key ('load', 'erase'
                    # etc.) to create a command object. The helper function knows
                    # how to handle the parameters of each command.
                    cmd_fce = sb21_helper.get_command(key)
                    if key in ("keywrap", "encrypt"):
                        keyblob = {"keyblobs": keyblobs}
                        value.update(keyblob)
                    cmd = cmd_fce(value)
                    commands.append(cmd)

            sb_sections.append(
                BootSectionV2(section_id, *commands, zero_filling=advanced_params.zero_padding)
            )

        # We have a list of sections and their respective commands, lets create
        # a boot image v2.1 object
        secure_binary = cls(
            sb_kek,
            *sb_sections,
            product_version=product_version,
            component_version=component_version,
            build_number=cert_block.header.build_number,
            flags=flags,
            advanced_params=advanced_params,
        )

        # We have our secure binary, now we attach to it the certificate block and
        # the private key content
        secure_binary.cert_block = cert_block

        if not signature_provider:
            signature_provider = Signing()

        secure_binary.signature_provider = signature_provider

        if secure_binary.cert_block:
            if not rkth_out_path:
                if "RKTHOutputPath" in config:
                    rkth_out_path = config.get_output_file_name("RKTHOutputPath")
                    # Only write the file if a path was explicitly provided
                    write_file(secure_binary.cert_block.rkth, rkth_out_path, mode="wb")
            else:
                # rkth_out_path was provided, so write the file
                assert isinstance(rkth_out_path, str), "Hash of hashes path must be string"
                write_file(secure_binary.cert_block.rkth, rkth_out_path, mode="wb")

        return secure_binary

    def encode_signature(self, raw_sig: bytes) -> bytes:
        try:
            ecdsa_sig = ECDSASignature.parse(raw_sig)
            signature = ecdsa_sig.export(SPSDKEncoding.NXP)
            return signature
        except SPSDKError as exc:
            raise SPSDKError("Not an ECC Signature") from exc

    # pylint: disable=too-many-locals
    def export(self, padding: Optional[bytes] = None) -> bytes:
        """Export SB2 image to binary format.

        The method validates all required components, updates internal structures, and exports
        the complete SB2 image including header, certificates, boot sections, and signature.

        :param padding: Header padding (8 bytes) for testing purpose; None to use random values
        :return: Complete SB2 image as binary data
        :raises SPSDKError: No boot section available for export
        :raises SPSDKError: Certificate block not assigned
        :raises SPSDKError: Signature provider not assigned
        :raises SPSDKError: Invalid header nonce value
        """
        # validate params
        if not self.boot_sections:
            raise SPSDKError("At least one Boot Section must be added")
        if self.cert_block is None:
            raise SPSDKError("Certificate is not assigned")
        if self.signature_provider is None:
            raise SPSDKError("Signature provider is not assigned, cannot sign the image")
        # Update internals
        self.update()
        # Export Boot Sections
        bs_data = bytes()
        bs_offset = (
            ImageHeaderV2.SIZE
            + self.HEADER_MAC_SIZE
            + self.KEY_BLOB_SIZE
            + self.cert_block.raw_size
            + self.cert_block.signature_size
        )
        if self.header.flags & self.FLAGS_SHA_PRESENT_BIT:
            bs_offset += self.SHA_256_SIZE

        if not self._header.nonce:
            raise SPSDKError("Invalid header's nonce")
        counter = Counter(self._header.nonce, SecBootBlckSize.to_num_blocks(bs_offset))
        for sect in self.boot_sections:
            bs_data += sect.export(dek=self.dek, mac=self.mac, counter=counter)
        # Export Header
        signed_data = self._header.export(padding=padding)
        #  Add HMAC data
        first_bs_hmac_count = self.boot_sections[0].hmac_count
        hmac_data = bs_data[CmdHeader.SIZE : CmdHeader.SIZE + (first_bs_hmac_count * 32) + 32]
        hmac_bytes = hmac(self.mac, hmac_data)
        signed_data += hmac_bytes
        # Add KeyBlob data
        key_blob = aes_key_wrap(self.kek, self.dek + self.mac)
        key_blob += b"\00" * (self.KEY_BLOB_SIZE - len(key_blob))
        signed_data += key_blob
        # Add Certificates data
        signed_data += self.cert_block.export()
        # Add SHA-256 of Bootable sections if requested
        if self.header.flags & self.FLAGS_SHA_PRESENT_BIT:
            signed_data += get_hash(bs_data)
        # Add Signature data
        raw_sig = self.signature_provider.sign(signed_data)
        signature = self.encode_signature(raw_sig)

        return signed_data + signature + bs_data
