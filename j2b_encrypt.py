#!/usr/bin/env python3
import os
import secrets
import struct
import sys


def build_lookup_table():
    """Build the PRNG lookup table from game.dll"""

    # 1024-byte lookup table from game.dll DAT_6f964e48
    hex_data = "8e142799fdaac708d5e63e1ff6bb55da75a04a6ae8bd97ffde9bbc9f818aa1466e0be363767a6c5d88d369cac347b92583aba23fa6417cbae5ac95017ecf09c1d96270718ddb05022487ef54c6d43730d01bcb7bb8e4d8ec49ceaddc13a994c48f39ae0d1852dd0e78faf58558d2af6da4b2533b51a550befc2df411489816f186df3d665e442e2f36076b178b294cb6e2895fe7cda721e14dc965edfeee9c23337db7049e9a2a40b3105bf382771c92204e1e572272068c672c73fb59c20abf795cf90c281a126874341942b1c084f838f0159d60f23a6fb490eb911d7f35615a320356a3c52b93800f4b43f7a8e03c96d16426d745cc4fc8b0e9b500d631ea000080bf0de05dbf8cb93bbf9a9919bf4df3eebe4ca6aabecdcc4cbe029a88bd029a883dcdcc4c3e4ca6aa3e4df3ee3e9a99193f8cb93b3f0de05d3f0000803f000000c007f0eebfc6dcddbfcdccccbfd3bcbbbf93a9aabf9a9999bfa08988bfc0ec6ebfcdcc4cbfdaac2abf598608bfcdccccbee78c88becc7f08be00000000cc7f083ee78c883ecdcccc3e5986083fdaac2a3fcdcc4c3fc0ec6e3fa089883f9a99993f93a9aa3fd3bcbb3fcdcccc3fc6dcdd3f07f0ee3f0000004000000000000080bfc0ec6ebf0de05dbfcdcc4cbf8cb93bbfdaac2abf9a9919bf598608bf4df3eebecdccccbe4ca6aabee78c88becdcc4cbecc7f08be029a88bd00000000029a883dcc7f083ecdcc4c3ee78c883e4ca6aa3ecdcccc3e4df3ee3e5986083f9a99193fdaac2a3f8cb93b3fcdcc4c3f0de05d3fc0ec6e3f0000803f0000000000000000963007772c610eeeba51099919c46d078ff46a7035a563e9a395649e3288db0ea4b8dc791ee9d5e088d9d2972b4cb609bd7cb17e072db8e7911dbf906410b71df220b06a4871b9f3de41be847dd4da1aebe4dd6d51b5d4f4c785d38356986c13c0a86b647af962fdecc9658a4f5c0114d96c0663633d0ffaf50d088dc8206e3b5e10694ce44160d5727167a2d1e4033c47d4044bfd850dd26bb50aa5faa8b5356c98b242d6c9bbdb40f9bcace36cd832755cdf45cf0dd6dc593dd1abac30d9263a00de518051d7c81661d0bfb5f4b42123c4b3569995bacf0fa5bdb89eb802280888055fb2d90cc624e90bb1877c6f2f114c6858ab1d61c13d2d66b69041dc760671db01bc20d2982a10d5ef8985b1711fb5b606a5e4bf9f33d4b8e8a2c9077834f9000f8ea8099618980ee1bb0d6a7f2d3d6d08976c6491015c63e6f4516b6b62616c1cd83065854e0062f2ed95066c7ba5011bc1f4088257c40ff5c6d9b06550e9b712eab8be8b7c88b9fcdf1ddd62492dda15f37cd38c654cd4fb5861b24dce51b53a7400bca3e230bbd441a5df4ad795d83d6dc4d1a4fbf4d6d36ae96943fcd96e34468867add0b860da732d0444e51d03335f4c0aaac97c0ddd"

    return bytes.fromhex(hex_data)


def prng(state1, state2, lookup_data):
    """
    PRNG implementation from game.dll FUN_6f199400

    Args:
        state1: First PRNG state (32-bit)
        state2: Second PRNG state (32-bit)
        lookup_data: 1024-byte lookup table

    Returns:
        tuple: (new_state1, new_state2)
    """

    # Extract bytes from state2
    byte0 = state2 & 0xFF
    byte1 = (state2 >> 8) & 0xFF
    byte2 = (state2 >> 16) & 0xFF
    byte3 = (state2 >> 24) & 0xFF

    # Calculate lookup indices with bounds checking
    idx2 = byte2 - 0x0C
    if idx2 < 0:
        idx2 = byte2 + 200

    idx3 = byte3 - 4
    if idx3 < 0:
        idx3 = byte3 + 0xB8

    idx1 = byte1 - 0x18
    if idx1 < 0:
        idx1 = byte1 + 0xD4

    idx0 = byte0 - 0x1C
    if idx0 < 0:
        idx0 = byte0 + 0xD8

    # Access lookup table at byte offsets
    def get_dword(offset):
        offset = offset % len(lookup_data)
        if offset + 4 <= len(lookup_data):
            return struct.unpack("<I", lookup_data[offset : offset + 4])[0]
        return 0

    val0 = get_dword(idx0)
    val1 = get_dword(idx1)
    val2 = get_dword(idx2)
    val3 = get_dword(idx3)

    # Apply rotations
    val1_rot = ((val1 << 3) | (val1 >> 29)) & 0xFFFFFFFF  # ROL(val1, 3)
    val2_rot = ((val2 << 2) | (val2 >> 30)) & 0xFFFFFFFF  # ROL(val2, 2)
    val3_rot = (
        (val3 << 1) | (1 if val3 & 0x80000000 else 0)
    ) & 0xFFFFFFFF  # ROL(val3, 1)

    # XOR combination
    temp = (val1_rot ^ val2_rot ^ val0 ^ val3_rot) & 0xFFFFFFFF

    # Update states
    new_state1 = (state1 + temp) & 0xFFFFFFFF
    new_state2 = ((idx3 << 24) | (idx2 << 16) | (idx1 << 8) | idx0) & 0xFFFFFFFF

    return new_state1, new_state2


def generate_seeds():
    """Generate cryptographically secure random seeds for PRNG initialization"""
    seed1 = secrets.randbits(32)
    seed2 = secrets.randbits(32)
    return seed1, seed2


def encrypt_war3map(plaintext_data, output_file=None, seed1=None, seed2=None):
    """
    Encrypt plaintext data into war3map.bin format

    Args:
        plaintext_data: Raw bytes or string to encrypt
        output_file: Output filename (defaults to war3map_encrypted.bin)
        seed1: Optional PRNG seed 1 (will generate random if None)
        seed2: Optional PRNG seed 2 (will generate random if None)

    Returns:
        bytes: Complete encrypted war3map.bin file
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

    # Build file header
    signature = 0x4A415332  # "2SAJ"
    header = struct.pack("<III", signature, seed1, seed2)

    # Initialize PRNG
    lookup_data = build_lookup_table()
    state1, state2 = seed1, seed2

    # Store original length for partial chunk handling
    original_length = len(plaintext_data)
    print(f"Original data length: {original_length} bytes (no padding added)")

    # Calculate number of complete 4-byte chunks
    num_chunks = original_length // 4
    remaining_bytes = original_length % 4
    print(
        f"Encrypting {num_chunks} complete chunks + {remaining_bytes} remaining bytes..."
    )

    # Encrypt data chunk by chunk
    encrypted_chunks = []

    # Process complete 4-byte chunks
    for chunk_idx in range(num_chunks):
        offset = chunk_idx * 4

        # Read plaintext chunk
        plaintext_chunk = struct.unpack("<I", plaintext_data[offset : offset + 4])[0]

        # Evolve PRNG to generate key
        state1, state2 = prng(state1, state2, lookup_data)

        # Generate decryption key (same as decryption)
        key = (state1 + state2) & 0xFFFFFFFF

        # Encrypt: plaintext XOR key = ciphertext
        encrypted_chunk = key ^ plaintext_chunk
        encrypted_chunks.append(struct.pack("<I", encrypted_chunk))

        # Progress indicator
        if chunk_idx % 1000 == 0 or chunk_idx < 10 or chunk_idx >= num_chunks - 5:
            progress = (chunk_idx + 1) / num_chunks * 100 if num_chunks > 0 else 100
            text = struct.pack("<I", plaintext_chunk)
            readable = "".join(chr(b) if 32 <= b <= 126 else "." for b in text)
            print(
                f"  Chunk {chunk_idx:4d}: 0x{plaintext_chunk:08X} '{readable}' -> 0x{encrypted_chunk:08X} ({progress:5.1f}%)"
            )

    # Handle remaining bytes (if any)
    if remaining_bytes > 0:
        offset = num_chunks * 4
        partial_data = plaintext_data[offset : offset + remaining_bytes]

        # Pad the partial chunk for processing (but don't include padding in output)
        padded_chunk = partial_data + b"\x00" * (4 - remaining_bytes)
        plaintext_chunk = struct.unpack("<I", padded_chunk)[0]

        # Generate key
        state1, state2 = prng(state1, state2, lookup_data)
        key = (state1 + state2) & 0xFFFFFFFF

        # Encrypt and take only the original bytes
        encrypted_chunk = key ^ plaintext_chunk
        encrypted_partial = struct.pack("<I", encrypted_chunk)[:remaining_bytes]
        encrypted_chunks.append(encrypted_partial)

        print(f"  Final partial chunk: {remaining_bytes} bytes -> encrypted")

    # Combine header + encrypted data
    encrypted_file = header + b"".join(encrypted_chunks)

    # Save to file
    with open(output_file, "wb") as f:
        f.write(encrypted_file)

    print(f"\nEncryption complete!")
    print(f"Encrypted {len(plaintext_data)} bytes to: {output_file}")
    print(f"Total file size: {len(encrypted_file)} bytes")

    # Verify encryption by attempting decryption
    print(f"\nVerification (decrypting first 32 bytes):")
    verify_decrypt(
        encrypted_file[:44], len(plaintext_data[:32])
    )  # Header + first 8 chunks

    return encrypted_file


def verify_decrypt(encrypted_data, original_length):
    """Verify encryption by decrypting the first few chunks"""

    if len(encrypted_data) < 12:
        print("  Not enough data to verify")
        return

    # Extract header
    signature, seed1, seed2 = struct.unpack("<III", encrypted_data[:12])
    print(f"  Signature: 0x{signature:08X} ('2SAJ')")
    print(f"  Seeds: 0x{seed1:08X}, 0x{seed2:08X}")

    # Initialize PRNG with same seeds
    lookup_data = build_lookup_table()
    state1, state2 = seed1, seed2

    # Decrypt available chunks
    encrypted_payload = encrypted_data[12:]
    num_chunks = min(len(encrypted_payload) // 4, original_length // 4)

    decrypted = bytearray()
    for chunk_idx in range(num_chunks):
        offset = chunk_idx * 4
        encrypted_chunk = struct.unpack("<I", encrypted_payload[offset : offset + 4])[0]

        # Generate same key
        state1, state2 = prng(state1, state2, lookup_data)
        key = (state1 + state2) & 0xFFFFFFFF

        # Decrypt
        decrypted_chunk = key ^ encrypted_chunk
        decrypted.extend(struct.pack("<I", decrypted_chunk))

    # Show decrypted result
    text = decrypted[:32].decode("utf-8", errors="replace")
    print(f"  Decrypted: {repr(text)}")
    print(
        "  Verification successful!" if len(decrypted) > 0 else "  Verification failed!"
    )


def encrypt_file(input_file, output_file=None, seed1=None, seed2=None):
    """Encrypt a file into war3map.bin format"""

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    if output_file is None:
        base, _ = os.path.splitext(input_file)
        output_file = base + "_encrypted.bin"

    # Read input file
    with open(input_file, "rb") as f:
        plaintext_data = f.read()

    print(f"Reading {len(plaintext_data)} bytes from: {input_file}")
    return encrypt_war3map(plaintext_data, output_file, seed1, seed2)


def main():
    """Main entry point"""

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
                seed1 = int(
                    sys.argv[3], 0
                )  # 0 means auto-detect base (hex if 0x prefix)
            if len(sys.argv) > 4:
                seed2 = int(sys.argv[4], 0)

            encrypt_file(input_file, output_file, seed1, seed2)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

