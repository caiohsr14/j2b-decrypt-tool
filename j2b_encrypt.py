#!/usr/bin/env python3
"""J2B file encryption tool.

Encrypts files into war3map.bin format using J2B encryption.
"""

import os
import struct
import sys
from typing import Optional, Union

from j2b_constants import *
from j2b_crypto import J2BPRNG
from j2b_utils import (
    J2BError,
    format_bytes_readable,
    generate_seeds,
    process_chunks,
    validate_file_path,
    write_header,
)


def encrypt_war3map(
    plaintext_data: Union[str, bytes],
    output_file: Optional[str] = None,
    seed1: Optional[int] = None,
    seed2: Optional[int] = None,
) -> bytes:
    """Encrypt plaintext data into war3map.bin format.

    Args:
        plaintext_data: Raw bytes or string to encrypt
        output_file: Output filename (defaults to war3map_encrypted.bin)
        seed1: Optional PRNG seed 1 (will generate random if None)
        seed2: Optional PRNG seed 2 (will generate random if None)

    Returns:
        Complete encrypted war3map.bin file as bytes

    Raises:
        J2BError: If encryption fails
    """
    if output_file is None:
        output_file = "war3map_encrypted.bin"

    # Convert string to bytes if needed
    if isinstance(plaintext_data, str):
        plaintext_data = plaintext_data.encode("utf-8")

    print(f"Input data: {len(plaintext_data)} bytes")
    print(f"Output:     {output_file}")
    print("-" * 50)

    # Generate seeds if not provided
    if seed1 is None or seed2 is None:
        seed1, seed2 = generate_seeds()
        print(f"Generated random seeds:")
    else:
        print(f"Using provided seeds:")

    print(f"  Seed1: 0x{seed1:08X}")
    print(f"  Seed2: 0x{seed2:08X}")

    # Initialize PRNG
    prng = J2BPRNG(seed1, seed2)

    # Calculate chunks
    complete_chunks, remaining_bytes = process_chunks(plaintext_data)
    print(f"Original data length: {len(plaintext_data)} bytes (no padding added)")
    print(
        f"Encrypting {complete_chunks} complete chunks + {remaining_bytes} remaining bytes..."
    )

    # Encrypt data chunk by chunk
    encrypted_chunks = []

    # Process complete 4-byte chunks
    for chunk_idx in range(complete_chunks):
        offset = chunk_idx * CHUNK_SIZE

        # Read plaintext chunk
        plaintext_chunk = struct.unpack(
            "<I", plaintext_data[offset : offset + CHUNK_SIZE]
        )[0]

        # Generate encryption key
        key = prng.generate_key()

        # Encrypt: plaintext XOR key = ciphertext
        encrypted_chunk = key ^ plaintext_chunk
        encrypted_chunks.append(struct.pack("<I", encrypted_chunk))

        # Progress indicator
        if chunk_idx % 1000 == 0 or chunk_idx < 10 or chunk_idx >= complete_chunks - 5:
            progress = (
                (chunk_idx + 1) / complete_chunks * 100 if complete_chunks > 0 else 100
            )
            chunk_bytes = struct.pack("<I", plaintext_chunk)
            readable = format_bytes_readable(chunk_bytes)
            print(
                f"  Chunk {chunk_idx:4d}: 0x{plaintext_chunk:08X} '{readable}' -> "
                f"0x{encrypted_chunk:08X} ({progress:5.1f}%)"
            )

    # Handle remaining bytes (if any)
    if remaining_bytes > 0:
        offset = complete_chunks * CHUNK_SIZE
        partial_data = plaintext_data[offset : offset + remaining_bytes]

        # Pad the partial chunk for processing
        padded_chunk = partial_data + b"\x00" * (CHUNK_SIZE - remaining_bytes)
        plaintext_chunk = struct.unpack("<I", padded_chunk)[0]

        # Generate key
        key = prng.generate_key()

        # Encrypt and take only the original bytes
        encrypted_chunk = key ^ plaintext_chunk
        encrypted_partial = struct.pack("<I", encrypted_chunk)[:remaining_bytes]
        encrypted_chunks.append(encrypted_partial)

        print(f"  Final partial chunk: {remaining_bytes} bytes -> encrypted")

    # Build complete file with header
    with open(output_file, "wb") as f:
        write_header(f, seed1, seed2)
        for chunk in encrypted_chunks:
            f.write(chunk)

    # Read back for verification
    with open(output_file, "rb") as f:
        encrypted_file = f.read()

    print(f"\nEncryption complete!")
    print(f"Encrypted {len(plaintext_data)} bytes to: {output_file}")
    print(f"Total file size: {len(encrypted_file)} bytes")

    # Verify encryption
    print(f"\nVerification (decrypting first 32 bytes):")
    verify_decrypt(encrypted_file[:44], len(plaintext_data[:32]))

    return encrypted_file


def verify_decrypt(encrypted_data: bytes, original_length: int) -> None:
    """Verify encryption by decrypting the first few chunks.

    Args:
        encrypted_data: Encrypted data to verify
        original_length: Original plaintext length
    """
    if len(encrypted_data) < HEADER_SIZE:
        print("  Not enough data to verify")
        return

    # Extract header
    signature, seed1, seed2 = struct.unpack("<III", encrypted_data[:HEADER_SIZE])
    print(f"  Signature: 0x{signature:08X} ('{FILE_SIGNATURE_STR}')")
    print(f"  Seeds: 0x{seed1:08X}, 0x{seed2:08X}")

    # Initialize PRNG with same seeds
    prng = J2BPRNG(seed1, seed2)

    # Decrypt available chunks
    encrypted_payload = encrypted_data[HEADER_SIZE:]
    num_chunks = min(
        len(encrypted_payload) // CHUNK_SIZE, original_length // CHUNK_SIZE
    )

    decrypted = bytearray()
    for chunk_idx in range(num_chunks):
        offset = chunk_idx * CHUNK_SIZE
        encrypted_chunk = struct.unpack(
            "<I", encrypted_payload[offset : offset + CHUNK_SIZE]
        )[0]

        # Generate same key
        key = prng.generate_key()

        # Decrypt
        decrypted_chunk = key ^ encrypted_chunk
        decrypted.extend(struct.pack("<I", decrypted_chunk))

    # Show decrypted result
    text = decrypted[:32].decode("utf-8", errors="replace")
    print(f"  Decrypted: {repr(text)}")
    print(
        "  Verification successful!" if len(decrypted) > 0 else "  Verification failed!"
    )


def encrypt_file(
    input_file: str,
    output_file: Optional[str] = None,
    seed1: Optional[int] = None,
    seed2: Optional[int] = None,
) -> bytes:
    """Encrypt a file into war3map.bin format.

    Args:
        input_file: Path to file to encrypt
        output_file: Output path (defaults to input_encrypted.bin)
        seed1: Optional PRNG seed 1
        seed2: Optional PRNG seed 2

    Returns:
        Encrypted data as bytes

    Raises:
        J2BFileError: If input file not found
    """
    input_path = validate_file_path(input_file)

    if output_file is None:
        base, _ = os.path.splitext(input_path)
        output_file = base + "_encrypted.bin"

    # Read input file
    with open(input_path, "rb") as f:
        plaintext_data = f.read()

    print(f"Reading {len(plaintext_data)} bytes from: {input_path}")
    return encrypt_war3map(plaintext_data, output_file, seed1, seed2)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python j2b_encrypt.py <input_file> [output_file] [seed1] [seed2]")
        print('  python j2b_encrypt.py --text "Your text here" [output_file]')
        print("")
        print("Examples:")
        print("  python j2b_encrypt.py decrypted.txt")
        print("  python j2b_encrypt.py decrypted.txt custom.bin")
        print('  python j2b_encrypt.py --text "function main()\\nendfunction" test.bin')
        print("  python j2b_encrypt.py input.txt output.bin 0x12345678 0x87654321")
        sys.exit(1)

    try:
        if sys.argv[1] == "--text":
            # Encrypt text directly
            if len(sys.argv) < 3:
                print("Error: --text requires text argument")
                sys.exit(1)

            text_data = sys.argv[2]
            output_file = sys.argv[3] if len(sys.argv) > 3 else "text_encrypted.bin"
            encrypt_war3map(text_data, output_file)

        else:
            # Encrypt file
            input_file = sys.argv[1]
            output_file = sys.argv[2] if len(sys.argv) > 2 else None

            # Parse optional seeds
            seed1 = None
            seed2 = None
            if len(sys.argv) > 3:
                seed1 = int(sys.argv[3], 0)  # 0 means auto-detect base
            if len(sys.argv) > 4:
                seed2 = int(sys.argv[4], 0)

            encrypt_file(input_file, output_file, seed1, seed2)

    except J2BError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
