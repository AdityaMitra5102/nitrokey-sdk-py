#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for key generation and saving keys to file."""

import abc
import math
from abc import abstractmethod
from enum import Enum
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.serialization import PublicFormat
from typing_extensions import Self

from ..exceptions import SPSDKError
from ..utils.misc import Endianness
from .hash import EnumHashAlgorithm, get_hash, get_hash_algorithm
from .types import SPSDKEncoding


class PublicKey(abc.ABC):
    """SPSDK Public Key."""

    key: Any

    @property
    @abc.abstractmethod
    def signature_size(self) -> int:
        """Size of signature data."""

    @property
    @abc.abstractmethod
    def public_numbers(self) -> Any:
        """Public numbers."""

    @abc.abstractmethod
    def verify_signature(
        self, signature: bytes, data: bytes, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256
    ) -> bool:
        """Verify input data.

        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm
        :return: True if signature is valid, False otherwise
        """

    @abc.abstractmethod
    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Export key into bytes to requested format.

        :param encoding: encoding type, default is NXP
        :return: Byte representation of key
        """

    def key_hash(self, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256) -> bytes:
        """Get key hash.

        :param algorithm: Used hash algorithm, defaults to sha256
        :return: Key Hash
        """
        return get_hash(self.export(), algorithm)

    def __eq__(self, obj: Any) -> bool:
        """Check object equality."""
        return isinstance(obj, self.__class__) and self.public_numbers == obj.public_numbers

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    @abstractmethod
    def __repr__(self) -> str:
        """Object representation in string format."""

    @abstractmethod
    def __str__(self) -> str:
        """Object description in string format."""


# ===================================================================================================
# ===================================================================================================
#
#                                      RSA Keys
#
# ===================================================================================================
# ===================================================================================================


class PublicKeyRsa(PublicKey):
    """SPSDK Public Key."""

    SUPPORTED_KEY_SIZES = [2048, 3072, 4096]

    key: rsa.RSAPublicKey

    def __init__(self, key: rsa.RSAPublicKey) -> None:
        """Create SPSDK Public Key.

        :param key: SPSDK Public Key data or file path
        """
        self.key = key

    @property
    def signature_size(self) -> int:
        """Size of signature data."""
        return self.key.key_size // 8

    @property
    def key_size(self) -> int:
        """Key size in bits.

        :return: Key Size
        """
        return self.key.key_size

    @property
    def public_numbers(self) -> rsa.RSAPublicNumbers:
        """Public numbers of key.

        :return: Public numbers
        """
        return self.key.public_numbers()

    @property
    def e(self) -> int:
        """Public number E.

        :return: E
        """
        return self.public_numbers.e

    @property
    def n(self) -> int:
        """Public number N.

        :return: N
        """
        return self.public_numbers.n

    def export(
        self,
        encoding: SPSDKEncoding = SPSDKEncoding.NXP,
        exp_length: Optional[int] = None,
        modulus_length: Optional[int] = None,
    ) -> bytes:
        """Save the public key to the bytes in NXP or DER format.

        :param encoding: encoding type, default is NXP
        :param exp_length: Optional specific exponent length in bytes
        :param modulus_length: Optional specific modulus length in bytes
        :returns: Public key in bytes
        """
        if encoding == SPSDKEncoding.NXP:
            exp_rotk = self.e
            mod_rotk = self.n
            exp_length = exp_length or math.ceil(exp_rotk.bit_length() / 8)
            modulus_length = modulus_length or math.ceil(mod_rotk.bit_length() / 8)
            exp_rotk_bytes = exp_rotk.to_bytes(exp_length, Endianness.BIG.value)
            mod_rotk_bytes = mod_rotk.to_bytes(modulus_length, Endianness.BIG.value)
            return mod_rotk_bytes + exp_rotk_bytes

        return self.key.public_bytes(
            SPSDKEncoding.get_cryptography_encodings(encoding), PublicFormat.PKCS1
        )

    def verify_signature(
        self, signature: bytes, data: bytes, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256
    ) -> bool:
        """Verify input data.

        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm
        :return: True if signature is valid, False otherwise
        """
        try:
            self.key.verify(
                signature=signature,
                data=data,
                padding=padding.PKCS1v15(),
                algorithm=get_hash_algorithm(algorithm),
            )
        except InvalidSignature:
            return False

        return True

    def __eq__(self, obj: Any) -> bool:
        """Check object equality."""
        return isinstance(obj, self.__class__) and self.public_numbers == obj.public_numbers

    def __repr__(self) -> str:
        return f"RSA{self.key_size} Public Key"

    def __str__(self) -> str:
        """Object description in string format."""
        ret = f"RSA{self.key_size} Public key: \ne({hex(self.e)}) \nn({hex(self.n)})"
        return ret


class EccCurve(str, Enum):
    """Enumeration of supported elliptic curve cryptographic key types.

    This enumeration defines the elliptic curve types that are supported
    by SPSDK cryptographic operations for ECC key generation and processing.
    """

    SECP256R1 = "secp256r1"
    SECP384R1 = "secp384r1"
    SECP521R1 = "secp521r1"
    BRAINPOOLP256R1 = "brainpoolP256r1"
    BRAINPOOLP384R1 = "brainpoolP384r1"
    BRAINPOOLP512R1 = "brainpoolP512r1"


class ECDSASignature:
    """ECDSA Signature representation and manipulation.

    This class provides functionality for handling ECDSA signatures including parsing
    from different formats (DER, NXP), exporting to various encodings, and managing
    signature components (r, s values) along with their associated ECC curve parameters.

    :cvar COORDINATE_LENGTHS: Mapping of ECC curves to their coordinate byte lengths.
    """

    COORDINATE_LENGTHS = {EccCurve.SECP256R1: 32, EccCurve.SECP384R1: 48, EccCurve.SECP521R1: 66}

    def __init__(self, r: int, s: int, ecc_curve: EccCurve) -> None:
        """Initialize ECDSA signature with r and s values.

        Creates an ECDSA signature object containing the mathematical components
        of the signature along with the associated elliptic curve parameters.

        :param r: The r component of the ECDSA signature (x-coordinate of random point).
        :param s: The s component of the ECDSA signature (calculated signature value).
        :param ecc_curve: The elliptic curve used for the signature generation.
        """
        self.r = r
        self.s = s
        self.ecc_curve = ecc_curve

    @classmethod
    def parse(cls, signature: bytes) -> Self:
        """Parse signature in DER or NXP format.

        The method automatically detects the encoding format and creates an instance with the parsed
        signature components (r, s) and the appropriate ECC curve.

        :param signature: Binary signature data in either DER or NXP format.
        :raises SPSDKError: Invalid signature encoding format.
        :return: New instance with parsed signature components.
        """
        encoding = cls.get_encoding(signature)
        if encoding == SPSDKEncoding.DER:
            r, s = utils.decode_dss_signature(signature)
            ecc_curve = cls.get_ecc_curve(len(signature))
            return cls(r, s, ecc_curve)
        if encoding == SPSDKEncoding.NXP:
            r = int.from_bytes(signature[: len(signature) // 2], Endianness.BIG.value)
            s = int.from_bytes(signature[len(signature) // 2 :], Endianness.BIG.value)
            ecc_curve = cls.get_ecc_curve(len(signature))
            return cls(r, s, ecc_curve)
        raise SPSDKError(f"Invalid signature encoding {encoding.value}")

    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Export signature in DER or NXP format.

        The method converts the signature's r and s coordinates into the specified encoding format.
        For NXP encoding, it concatenates the r and s values as big-endian bytes. For DER encoding,
        it uses the standard ASN.1 DER format for DSS signatures.

        :param encoding: Signature encoding format (NXP or DER).
        :raises SPSDKError: Invalid signature encoding format.
        :return: Signature as bytes in the specified encoding format.
        """
        if encoding == SPSDKEncoding.NXP:
            r_bytes = self.r.to_bytes(self.COORDINATE_LENGTHS[self.ecc_curve], Endianness.BIG.value)
            s_bytes = self.s.to_bytes(self.COORDINATE_LENGTHS[self.ecc_curve], Endianness.BIG.value)
            return r_bytes + s_bytes
        if encoding == SPSDKEncoding.DER:
            return utils.encode_dss_signature(self.r, self.s)
        raise SPSDKError(f"Invalid signature encoding {encoding.value}")

    @classmethod
    def get_encoding(cls, signature: bytes) -> SPSDKEncoding:
        """Get encoding of signature.

        Detects the encoding format of a given signature by analyzing its length and structure.
        The method first checks for NXP format based on signature length, then attempts to
        decode as DER format.

        :param signature: The signature bytes to analyze for encoding detection.
        :raises SPSDKError: When signature doesn't match any supported encoding format.
        :return: The detected encoding format (NXP or DER).
        """
        signature_length = len(signature)
        # Try detect the NXP format by data length
        if signature_length // 2 in cls.COORDINATE_LENGTHS.values():
            return SPSDKEncoding.NXP
        # Try detect the DER format by decode of header
        try:
            utils.decode_dss_signature(signature)
            return SPSDKEncoding.DER
        except ValueError:
            pass
        raise SPSDKError(
            f"The given signature with length {signature_length} does not match any encoding"
        )

    @classmethod
    def get_ecc_curve(cls, signature_length: int) -> EccCurve:
        """Get the Elliptic Curve based on signature length.

        The method determines the appropriate ECC curve by matching the signature length
        against known coordinate lengths. It supports both exact matches and ranges
        for DER-encoded signatures.

        :param signature_length: Length of the signature in bytes
        :return: The corresponding ECC curve
        :raises SPSDKError: If signature length doesn't match any known ECC curve
        """
        for curve, coord_len in cls.COORDINATE_LENGTHS.items():
            if signature_length == coord_len * 2:
                return curve
            if signature_length in range(coord_len * 2 + 3, coord_len * 2 + 9):
                return curve
        raise SPSDKError(
            f"The given signature with length {signature_length} does not match any ecc curve"
        )
