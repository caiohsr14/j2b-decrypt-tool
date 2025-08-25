# WAR3MAP.BIN Decryption Algorithm - Complete Technical Documentation

## Overview

Tool to enable modifications on Warcraft 3 maps that use j2b encryption (wenhao_plugin.tga + callback + war3map.bin)

## File Structure

### Binary Format
```
Offset 0x00-0x03: Signature "2SAJ" (0x4A415332 little-endian)
Offset 0x04-0x07: PRNG Seed 1 (32-bit little-endian)
Offset 0x08-0x0B: PRNG Seed 2 (32-bit little-endian)  
Offset 0x0C-EOF:  Encrypted data in 4-byte chunks
```

## Usage example

After extracting war3map.bin from your .w3x file, decrypt it by using j2b_decrypt.py:
```bash
> python j2b_decrypt.py war3map.bin
Input:  war3map.bin
Output: war3map.bin.decrypted
--------------------------------------------------
Signature: 0x4A415332 ('2SAJ')
PRNG Seed1: 0x2C46961D
PRNG Seed2: 0x28D09424
File size: 12667619 bytes
Encrypted: 12667607 bytes (3166901 complete chunks + 3 remaining bytes)
...
Decryption complete!
Decrypted 12667607 bytes to: war3map.bin.decrypted
```

The resulting war3map.bin.decrypted file will be a binary file that the game understands containing strings and bytecode, from this point you can modify
it with any desired tool

After modifying it, you can encrypt it back to a new war3map.bin and replace it in your .w3x file:
```bash
> python j2b_encrypt.py war3map.bin.decrypted war3map.bin
Reading 12667607 bytes from: war3map.bin.decrypted
Input data: 12667607 bytes
Output:     war3map.bin
--------------------------------------------------
Generated random seeds:
  Seed1: 0x0931A9C5
  Seed2: 0xF853F63E
Original data length: 12667607 bytes (no padding added)
Encrypting 3166901 complete chunks + 3 remaining bytes...
...
Encryption complete!
Encrypted 12667607 bytes to: war3map.bin
Total file size: 12667619 bytes

Verification (decrypting first 32 bytes):
  Signature: 0x4A415332 ('2SAJ')
  Seeds: 0x0931A9C5, 0xF853F63E
  Decrypted: '�>\x00\x00main\x00agent\x00event\x00player\x00widg'
  Verification successful!
```

## Cryptographic Algorithm

### PRNG-Based Stream Cipher
The encryption uses a custom Pseudo-Random Number Generator (PRNG) to generate a keystream that is XORed with the plaintext data.

### PRNG Implementation
Based on reverse engineering of `game.dll` function `FUN_6f199400`:

```c
// PRNG state consists of two 32-bit integers
struct PRNGState {
    uint32_t state1;  // Accumulator
    uint32_t state2;  // Index generator
};

uint32_t prng_step(PRNGState* state, uint32_t lookup_table[256]) {
    // Extract bytes from state2 for lookup table indexing
    uint8_t byte0 = state->state2 & 0xFF;
    uint8_t byte1 = (state->state2 >> 8) & 0xFF;
    uint8_t byte2 = (state->state2 >> 16) & 0xFF;
    uint8_t byte3 = (state->state2 >> 24) & 0xFF;
    
    // Calculate lookup indices with wraparound bounds checking
    uint8_t idx0 = (byte0 >= 0x1C) ? byte0 - 0x1C : byte0 + 0xD8;
    uint8_t idx1 = (byte1 >= 0x18) ? byte1 - 0x18 : byte1 + 0xD4;
    uint8_t idx2 = (byte2 >= 0x0C) ? byte2 - 0x0C : byte2 + 200;
    uint8_t idx3 = (byte3 >= 0x04) ? byte3 - 0x04 : byte3 + 0xB8;
    
    // Fetch values from lookup table
    uint32_t val0 = lookup_table[idx0];
    uint32_t val1 = lookup_table[idx1];
    uint32_t val2 = lookup_table[idx2];
    uint32_t val3 = lookup_table[idx3];
    
    // Apply bit rotations
    uint32_t val1_rot = (val1 << 3) | (val1 >> 29);  // ROL(val1, 3)
    uint32_t val2_rot = (val2 << 2) | (val2 >> 30);  // ROL(val2, 2)
    uint32_t val3_rot = (val3 << 1) | ((val3 & 0x80000000) ? 1 : 0);  // ROL(val3, 1)
    
    // XOR combination
    uint32_t temp = val1_rot ^ val2_rot ^ val0 ^ val3_rot;
    
    // Update PRNG states
    state->state1 = (state->state1 + temp) & 0xFFFFFFFF;
    state->state2 = (idx3 << 24) | (idx2 << 16) | (idx1 << 8) | idx0;
    
    return state->state1;
}
```

### Lookup Table
The PRNG uses a 1024-byte (256 × 32-bit) lookup table extracted from `game.dll` at address `0x6f964e48`:

```
8E142799 FDAAC708 D5E63E1F F6BB55DA 75A04A6A E8BD97FF DE9BBC9F 818AA146
6E0BE363 767A6C5D 88D369CA C347B925 83ABA23F A6417CBA E5AC9501 7ECF09C1
... [256 total 32-bit values]
```

### Decryption Process

1. **Initialize PRNG**: Use seeds from file offsets 4-8 and 8-12
2. **For each 4-byte chunk**:
   - Evolve PRNG state by calling `prng_step()`
   - Generate decryption key: `key = (state1 + state2) & 0xFFFFFFFF`
   - Decrypt chunk: `decrypted = encrypted_chunk XOR key`
3. **Concatenate** all decrypted chunks to produce plaintext

## Implementation Details

### Byte Offset Access Pattern
The decompiled code uses direct byte offset access into the lookup table:
```c
*(uint32_t*)(&lookup_table_base + byte_offset)
```
This means indices 0-255 access bytes 0-1023 in the lookup table.

### Self-Seeding Mechanism
The file contains its own PRNG initialization values:
- Seeds are stored unencrypted at file offsets 4-8 and 8-12
- No external key material required
- Each file can decrypt itself given the correct algorithm and lookup table

### Index Calculation Logic
The index calculation uses specific offset values and wraparound:
```
if (byte_value >= threshold) {
    index = byte_value - threshold;
} else {
    index = byte_value + wraparound_value;
}
```

Thresholds and wraparound values:
- Byte 0: threshold=0x1C, wraparound=0xD8
- Byte 1: threshold=0x18, wraparound=0xD4  
- Byte 2: threshold=0x0C, wraparound=200
- Byte 3: threshold=0x04, wraparound=0xB8

## Verification and Testing

### Known Test Vectors
From x64dbg runtime analysis:

**Initial State**: `(0x2C46961D, 0x28D09424)`
**After 1st iteration**: `(0xB9614EFC, 0x24C47C08)`

**Decrypted chunks**:
- Chunk 0: `0x00003E9F` (padding)
- Chunk 1: `0x6E69616D` ("main")
- Chunk 2: `0x65676100` ("age\0")

### Implementation Validation
The algorithm was validated by:
1. Step-by-step x64dbg trace analysis
2. ReVa static analysis of decompiled code
3. Successful decryption of complete 12.7MB file
4. Content structure verification (94.4% printable characters in API sections)

## Python Reference Implementation

```python
def decrypt_war3map(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Verify signature
    signature = struct.unpack('<I', data[0:4])[0]
    if signature != 0x4A415332:
        raise ValueError("Invalid signature")
    
    # Extract seeds
    seed1 = struct.unpack('<I', data[4:8])[0]
    seed2 = struct.unpack('<I', data[8:12])[0]
    
    # Initialize PRNG
    state1, state2 = seed1, seed2
    lookup_table = build_lookup_table()  # 1024-byte table from game.dll
    
    # Decrypt data
    decrypted = bytearray()
    for chunk_offset in range(12, len(data), 4):
        encrypted = struct.unpack('<I', data[chunk_offset:chunk_offset+4])[0]
        
        # Evolve PRNG
        state1, state2 = prng_step(state1, state2, lookup_table)
        
        # Generate key and decrypt
        key = (state1 + state2) & 0xFFFFFFFF
        decrypted_chunk = key ^ encrypted
        decrypted.extend(struct.pack('<I', decrypted_chunk))
    
    return bytes(decrypted)
```

## Encryption Implementation

The same PRNG algorithm can be used for encryption since it's a stream cipher:

```python
def encrypt_war3map(plaintext_data, seed1=None, seed2=None):
    """Encrypt plaintext data into war3map.bin format"""
    
    # Generate random seeds if not provided
    if seed1 is None or seed2 is None:
        seed1, seed2 = generate_seeds()
    
    # Create file header: signature + seeds
    header = struct.pack('<III', 0x4A415332, seed1, seed2)
    
    # Initialize PRNG with seeds
    lookup_data = build_lookup_table()
    state1, state2 = seed1, seed2
    
    # Encrypt data chunk by chunk
    encrypted_chunks = []
    for chunk_offset in range(0, len(plaintext_data), 4):
        plaintext_chunk = struct.unpack('<I', plaintext_data[chunk_offset:chunk_offset+4])[0]
        
        # Evolve PRNG to generate key
        state1, state2 = prng(state1, state2, lookup_data)
        key = (state1 + state2) & 0xFFFFFFFF
        
        # Encrypt: plaintext XOR key = ciphertext
        encrypted_chunk = key ^ plaintext_chunk
        encrypted_chunks.append(struct.pack('<I', encrypted_chunk))
    
    return header + b''.join(encrypted_chunks)
```
