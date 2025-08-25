#!/usr/bin/env python3
"""Core cryptographic functions for J2B encryption/decryption."""

import struct
from typing import Tuple


class J2BPRNG:
    """Pseudo-Random Number Generator for J2B encryption."""

    # Lookup table from game.dll DAT_6f964e48
    _LOOKUP_TABLE_HEX = (
        "8e142799fdaac708d5e63e1ff6bb55da75a04a6ae8bd97ffde9bbc9f818aa146"
        "6e0be363767a6c5d88d369cac347b92583aba23fa6417cbae5ac95017ecf09c1"
        "d96270718ddb05022487ef54c6d43730d01bcb7bb8e4d8ec49ceaddc13a994c4"
        "8f39ae0d1852dd0e78faf58558d2af6da4b2533b51a550befc2df411489816f1"
        "86df3d665e442e2f36076b178b294cb6e2895fe7cda721e14dc965edfeee9c23"
        "337db7049e9a2a40b3105bf382771c92204e1e572272068c672c73fb59c20abf"
        "795cf90c281a126874341942b1c084f838f0159d60f23a6fb490eb911d7f3561"
        "5a320356a3c52b93800f4b43f7a8e03c96d16426d745cc4fc8b0e9b500d631ea"
        "000080bf0de05dbf8cb93bbf9a9919bf4df3eebe4ca6aabecdcc4cbe029a88bd"
        "029a883dcdcc4c3e4ca6aa3e4df3ee3e9a99193f8cb93b3f0de05d3f0000803f"
        "000000c007f0eebfc6dcddbfcdccccbfd3bcbbbf93a9aabf9a9999bfa08988bf"
        "c0ec6ebfcdcc4cbfdaac2abf598608bfcdccccbee78c88becc7f08be00000000"
        "cc7f083ee78c883ecdcccc3e5986083fdaac2a3fcdcc4c3fc0ec6e3fa089883f"
        "9a99993f93a9aa3fd3bcbb3fcdcccc3fc6dcdd3f07f0ee3f00000040"
        "00000000000080bfc0ec6ebf0de05dbfcdcc4cbf8cb93bbfdaac2abf9a9919bf"
        "598608bf4df3eebecdccccbe4ca6aabee78c88becdcc4cbecc7f08be029a88bd"
        "00000000029a883dcc7f083ecdcc4c3ee78c883e4ca6aa3ecdcccc3e4df3ee3e"
        "5986083f9a99193fdaac2a3f8cb93b3fcdcc4c3f0de05d3fc0ec6e3f0000803f"
        "0000000000000000963007772c610eeeba51099919c46d078ff46a7035a563e9"
        "a395649e3288db0ea4b8dc791ee9d5e088d9d2972b4cb609bd7cb17e072db8e7"
        "911dbf906410b71df220b06a4871b9f3de41be847dd4da1aebe4dd6d51b5d4f4"
        "c785d38356986c13c0a86b647af962fdecc9658a4f5c0114d96c0663633d0ffa"
        "f50d088dc8206e3b5e10694ce44160d5727167a2d1e4033c47d4044bfd850dd2"
        "6bb50aa5faa8b5356c98b242d6c9bbdb40f9bcace36cd832755cdf45cf0dd6dc"
        "593dd1abac30d9263a00de518051d7c81661d0bfb5f4b42123c4b3569995bac"
        "f0fa5bdb89eb802280888055fb2d90cc624e90bb1877c6f2f114c6858ab1d61c"
        "13d2d66b69041dc760671db01bc20d2982a10d5ef8985b1711fb5b606a5e4bf9"
        "f33d4b8e8a2c9077834f9000f8ea8099618980ee1bb0d6a7f2d3d6d08976c649"
        "1015c63e6f4516b6b62616c1cd83065854e0062f2ed95066c7ba5011bc1f4088"
        "257c40ff5c6d9b06550e9b712eab8be8b7c88b9fcdf1ddd62492dda15f37cd38"
        "c654cd4fb5861b24dce51b53a7400bca3e230bbd441a5df4ad795d83d6dc4d1a"
        "4fbf4d6d36ae96943fcd96e34468867add0b860da732d0444e51d03335f4c0aa"
        "ac97c0ddd"
    )

    # Index calculation thresholds and wraparound values
    _INDEX_PARAMS = [
        (0x1C, 0xD8),  # byte0: threshold=0x1C, wraparound=0xD8
        (0x18, 0xD4),  # byte1: threshold=0x18, wraparound=0xD4
        (0x0C, 200),  # byte2: threshold=0x0C, wraparound=200
        (0x04, 0xB8),  # byte3: threshold=0x04, wraparound=0xB8
    ]

    def __init__(self, seed1: int, seed2: int):
        """Initialize PRNG with seeds.

        Args:
            seed1: First 32-bit seed
            seed2: Second 32-bit seed
        """
        self.state1 = seed1 & 0xFFFFFFFF
        self.state2 = seed2 & 0xFFFFFFFF
        self._lookup_table = bytes.fromhex(self._LOOKUP_TABLE_HEX)

    def step(self) -> Tuple[int, int]:
        """Advance PRNG state and return new state values.

        Returns:
            Tuple of (new_state1, new_state2)
        """
        # Extract bytes from state2
        bytes_from_state2 = [(self.state2 >> (i * 8)) & 0xFF for i in range(4)]

        # Calculate lookup indices with bounds checking
        indices = []
        for byte_val, (threshold, wraparound) in zip(
            bytes_from_state2, self._INDEX_PARAMS
        ):
            idx = byte_val - threshold
            if idx < 0:
                idx = byte_val + wraparound
            indices.append(idx)

        # Access lookup table at byte offsets
        values = []
        for idx in indices:
            offset = idx % len(self._lookup_table)
            if offset + 4 <= len(self._lookup_table):
                val = struct.unpack("<I", self._lookup_table[offset : offset + 4])[0]
            else:
                val = 0
            values.append(val)

        # Apply rotations
        val1_rot = ((values[1] << 3) | (values[1] >> 29)) & 0xFFFFFFFF  # ROL(val1, 3)
        val2_rot = ((values[2] << 2) | (values[2] >> 30)) & 0xFFFFFFFF  # ROL(val2, 2)
        val3_rot = (
            (values[3] << 1) | (1 if values[3] & 0x80000000 else 0)
        ) & 0xFFFFFFFF  # ROL(val3, 1)

        # XOR combination
        temp = (val1_rot ^ val2_rot ^ values[0] ^ val3_rot) & 0xFFFFFFFF

        # Update states
        self.state1 = (self.state1 + temp) & 0xFFFFFFFF
        self.state2 = (
            (indices[3] << 24) | (indices[2] << 16) | (indices[1] << 8) | indices[0]
        ) & 0xFFFFFFFF

        return self.state1, self.state2

    def generate_key(self) -> int:
        """Generate next encryption/decryption key.

        Returns:
            32-bit key value
        """
        self.step()
        return (self.state1 + self.state2) & 0xFFFFFFFF

