#!/usr/bin/env python3
"""
File structure:
- 4 bytes: "2SAJ" signature
- 4 bytes: PRNG seed 1 (not encrypted)
- 4 bytes: PRNG seed 2 (not encrypted)
- Remaining: Encrypted JASS/Lua code in 4-byte chunks
"""

import os
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


def decrypt_war3map(input_file, output_file=None, max_size=None):
    """
    Decrypt a war3map.bin file

    Args:
        input_file: Path to encrypted war3map.bin
        output_file: Output path (defaults to input_file.decrypted)
        max_size: Maximum bytes to decrypt (None for all)

    Returns:
        bytes: Decrypted data
    """

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    if output_file is None:
        output_file = input_file + ".decrypted"

    print(f"Input:  {input_file}")
    print(f"Output: {output_file}")
    print("-" * 50)

    # Read file
    with open(input_file, "rb") as f:
        data = f.read()

    if len(data) < 12:
        raise ValueError("File too small (minimum 12 bytes required)")

    # Verify signature
    signature = struct.unpack("<I", data[0:4])[0]
    if signature != 0x4A415332:  # "2SAJ"
        raise ValueError(f"Invalid signature: 0x{signature:08X} (expected 0x4A415332)")

    # Extract PRNG seeds
    seed1 = struct.unpack("<I", data[4:8])[0]
    seed2 = struct.unpack("<I", data[8:12])[0]

    print(f"Signature: 0x{signature:08X} ('2SAJ')")
    print(f"PRNG Seed1: 0x{seed1:08X}")
    print(f"PRNG Seed2: 0x{seed2:08X}")

    # Initialize PRNG
    lookup_data = build_lookup_table()
    state1, state2 = seed1, seed2

    # Determine how many chunks to decrypt
    encrypted_size = len(data) - 12
    complete_chunks = encrypted_size // 4
    remaining_bytes = encrypted_size % 4

    if max_size:
        complete_chunks = min(complete_chunks, max_size // 4)
        remaining_bytes = 0 if complete_chunks * 4 >= max_size else remaining_bytes

    print(f"File size: {len(data)} bytes")
    print(
        f"Encrypted: {encrypted_size} bytes ({complete_chunks} complete chunks + {remaining_bytes} remaining bytes)"
    )
    print(f"Decrypting...")

    # Decrypt data
    decrypted = bytearray()

    # Process complete 4-byte chunks
    for chunk in range(complete_chunks):
        offset = 12 + chunk * 4

        # Read encrypted chunk
        if offset + 4 > len(data):
            break

        encrypted = struct.unpack("<I", data[offset : offset + 4])[0]

        # Evolve PRNG
        state1, state2 = prng(state1, state2, lookup_data)

        # Generate decryption key
        key = (state1 + state2) & 0xFFFFFFFF

        # Decrypt chunk
        decrypted_chunk = key ^ encrypted
        decrypted.extend(struct.pack("<I", decrypted_chunk))

        # Progress indicator
        if chunk % 1000 == 0 or chunk < 10:
            progress = (
                (chunk + 1) / complete_chunks * 100 if complete_chunks > 0 else 100
            )
            text = struct.pack("<I", decrypted_chunk)
            readable = "".join(chr(b) if 32 <= b <= 126 else "." for b in text)
            print(
                f"  Chunk {chunk:4d}: 0x{decrypted_chunk:08X} '{readable}' ({progress:5.1f}%)"
            )

    # Handle remaining bytes (partial chunk)
    if remaining_bytes > 0:
        offset = 12 + complete_chunks * 4
        partial_data = data[offset : offset + remaining_bytes]

        # Pad to 4 bytes for decryption
        padded_chunk = partial_data + b"\x00" * (4 - remaining_bytes)
        encrypted = struct.unpack("<I", padded_chunk)[0]

        # Evolve PRNG one more time
        state1, state2 = prng(state1, state2, lookup_data)

        # Generate key and decrypt
        key = (state1 + state2) & 0xFFFFFFFF
        decrypted_chunk = key ^ encrypted

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
    """Main entry point"""

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
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

