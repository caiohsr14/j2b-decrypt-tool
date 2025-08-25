#!/usr/bin/env python3
"""J2B file decryption tool.

Decrypts war3map.bin files that use J2B encryption format.
"""

import struct
import sys
from typing import Optional

from j2b_constants import *
from j2b_crypto import J2BPRNG
from j2b_utils import (
    J2BError,
    format_bytes_readable,
    process_chunks,
    read_header,
    validate_file_path,
)


def decrypt_war3map(
    input_file: str, output_file: Optional[str] = None, max_size: Optional[int] = None
) -> bytes:
    """Decrypt a war3map.bin file.

    Args:
        input_file: Path to encrypted war3map.bin
        output_file: Output path (defaults to input_file.decrypted)
        max_size: Maximum bytes to decrypt (None for all)

    Returns:
        Decrypted data as bytes

    Raises:
        J2BError: If decryption fails
    """
    input_path = validate_file_path(input_file)

    if output_file is None:
        output_file = input_path + ".decrypted"

    print(f"Input:  {input_path}")
    print(f"Output: {output_file}")
    print("-" * 50)

    # Read file
    with open(input_path, "rb") as f:
        # Read and validate header
        signature, seed1, seed2 = read_header(f)

        print(f"Signature: 0x{signature:08X} ('{FILE_SIGNATURE_STR}')")
        print(f"PRNG Seed1: 0x{seed1:08X}")
        print(f"PRNG Seed2: 0x{seed2:08X}")

        # Read encrypted data
        encrypted_data = f.read()

    # Initialize PRNG
    prng = J2BPRNG(seed1, seed2)

    # Determine how many chunks to decrypt
    complete_chunks, remaining_bytes = process_chunks(encrypted_data)

    if max_size:
        complete_chunks = min(complete_chunks, max_size // CHUNK_SIZE)
        remaining_bytes = (
            0 if complete_chunks * CHUNK_SIZE >= max_size else remaining_bytes
        )

    print(f"File size: {len(encrypted_data) + HEADER_SIZE} bytes")
    print(
        f"Encrypted: {len(encrypted_data)} bytes "
        f"({complete_chunks} complete chunks + {remaining_bytes} remaining bytes)"
    )
    print(f"Decrypting...")

    # Decrypt data
    decrypted = bytearray()

    # Process complete 4-byte chunks
    for chunk_idx in range(complete_chunks):
        offset = chunk_idx * CHUNK_SIZE

        # Read encrypted chunk
        if offset + CHUNK_SIZE > len(encrypted_data):
            break

        encrypted_chunk = struct.unpack(
            "<I", encrypted_data[offset : offset + CHUNK_SIZE]
        )[0]

        # Generate decryption key
        key = prng.generate_key()

        # Decrypt chunk
        decrypted_chunk = key ^ encrypted_chunk
        decrypted.extend(struct.pack("<I", decrypted_chunk))

        # Progress indicator for first/last chunks and milestones
        if chunk_idx % 1000 == 0 or chunk_idx < 10:
            progress = (
                (chunk_idx + 1) / complete_chunks * 100 if complete_chunks > 0 else 100
            )
            chunk_bytes = struct.pack("<I", decrypted_chunk)
            readable = format_bytes_readable(chunk_bytes)
            print(
                f"  Chunk {chunk_idx:4d}: 0x{decrypted_chunk:08X} '{readable}' ({progress:5.1f}%)"
            )

    # Handle remaining bytes (partial chunk)
    if remaining_bytes > 0:
        offset = complete_chunks * CHUNK_SIZE
        partial_data = encrypted_data[offset : offset + remaining_bytes]

        # Pad to 4 bytes for decryption
        padded_chunk = partial_data + b"\x00" * (CHUNK_SIZE - remaining_bytes)
        encrypted_chunk = struct.unpack("<I", padded_chunk)[0]

        # Generate key and decrypt
        key = prng.generate_key()
        decrypted_chunk = key ^ encrypted_chunk

        # Take only the actual bytes (not padding)
        decrypted_partial = struct.pack("<I", decrypted_chunk)[:remaining_bytes]
        decrypted.extend(decrypted_partial)

        print(f"  Final partial chunk: {remaining_bytes} bytes decrypted")

    # Save decrypted data
    with open(output_file, "wb") as f:
        f.write(decrypted)

    print(f"\nDecryption complete!")
    print(f"Decrypted {len(decrypted)} bytes to: {output_file}")

    return bytes(decrypted)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python j2b_decrypt.py <input_file> [output_file] [max_bytes]")
        print("Example: python j2b_decrypt.py war3map.bin")
        print("Example: python j2b_decrypt.py war3map.bin decrypted.txt 10000")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    max_size = int(sys.argv[3]) if len(sys.argv) > 3 else None

    try:
        decrypt_war3map(input_file, output_file, max_size)
    except J2BError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
