#!/usr/bin/env python3
"""Utility functions for J2B encryption/decryption."""

import os
import secrets
import struct
from typing import BinaryIO, Optional, Tuple

from j2b_constants import *


class J2BError(Exception):
    """Base exception for J2B operations."""

    pass


class J2BFileError(J2BError):
    """Exception for file-related errors."""

    pass


class J2BFormatError(J2BError):
    """Exception for format-related errors."""

    pass


def read_header(file_handle: BinaryIO) -> Tuple[int, int, int]:
    """Read and validate J2B file header.

    Args:
        file_handle: Open file handle in binary read mode

    Returns:
        Tuple of (signature, seed1, seed2)

    Raises:
        J2BFormatError: If file is too small or has invalid signature
    """
    data = file_handle.read(HEADER_SIZE)

    if len(data) < HEADER_SIZE:
        raise J2BFormatError(f"File too small (minimum {HEADER_SIZE} bytes required)")

    signature, seed1, seed2 = struct.unpack("<III", data)

    if signature != FILE_SIGNATURE:
        raise J2BFormatError(
            f"Invalid signature: 0x{signature:08X} (expected 0x{FILE_SIGNATURE:08X})"
        )

    return signature, seed1, seed2


def write_header(file_handle: BinaryIO, seed1: int, seed2: int) -> None:
    """Write J2B file header.

    Args:
        file_handle: Open file handle in binary write mode
        seed1: First PRNG seed
        seed2: Second PRNG seed
    """
    header = struct.pack("<III", FILE_SIGNATURE, seed1, seed2)
    file_handle.write(header)


def generate_seeds() -> Tuple[int, int]:
    """Generate cryptographically secure random seeds.

    Returns:
        Tuple of (seed1, seed2) as 32-bit integers
    """
    return secrets.randbits(32), secrets.randbits(32)


def format_bytes_readable(data: bytes, max_len: int = 4) -> str:
    """Format bytes as readable string.

    Args:
        data: Bytes to format
        max_len: Maximum length to display

    Returns:
        String with printable characters or dots for non-printable
    """
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:max_len])


def validate_file_path(path: str, must_exist: bool = True) -> str:
    """Validate file path.

    Args:
        path: File path to validate
        must_exist: Whether file must exist

    Returns:
        Absolute path

    Raises:
        J2BFileError: If path is invalid
    """
    if must_exist and not os.path.exists(path):
        raise J2BFileError(f"File not found: {path}")

    return os.path.abspath(path)


def process_chunks(data: bytes, chunk_size: int = CHUNK_SIZE) -> Tuple[int, int]:
    """Calculate chunk counts for data.

    Args:
        data: Data to process
        chunk_size: Size of each chunk

    Returns:
        Tuple of (complete_chunks, remaining_bytes)
    """
    complete_chunks = len(data) // chunk_size
    remaining_bytes = len(data) % chunk_size
    return complete_chunks, remaining_bytes

