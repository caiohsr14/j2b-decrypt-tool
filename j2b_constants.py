#!/usr/bin/env python3
"""Constants for J2B file format."""

# File format constants
FILE_SIGNATURE = 0x4A415332  # "2SAJ" in little-endian
FILE_SIGNATURE_STR = "2SAJ"
HEADER_SIZE = 12  # Signature (4) + Seed1 (4) + Seed2 (4)
CHUNK_SIZE = 4

# File offsets
OFFSET_SIGNATURE = 0
OFFSET_SEED1 = 4
OFFSET_SEED2 = 8
OFFSET_DATA = 12

