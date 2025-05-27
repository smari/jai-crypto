


hmac :: (key: string, message: string, hash: (string) -> string, block_size: int = 64) -> string {
    block_sized_key := computeBlockSizedKey(key, hash, block_size);

    o_key_pad := block_sized_key ^ [0x5c block_size];
    i_key_pad := block_sized_key ^ [0x36 block_size];

    return hash(bytes_to_hex(o_key_pad) + hash(bytes_to_hex(i_key_pad) + message));
}

function hmac is
    input:
        key:        Bytes    // Array of bytes
        message:    Bytes    // Array of bytes to be hashed
        hash:       Function // The hash function to use (e.g. SHA-1)
        blockSize:  Integer  // The block size of the hash function (e.g. 64 bytes for SHA-1)
        outputSize: Integer  // The output size of the hash function (e.g. 20 bytes for SHA-1)

    // Compute the block sized key
    block_sized_key = computeBlockSizedKey(key, hash, blockSize)

    o_key_pad ← block_sized_key xor [0x5c blockSize]   // Outer padded key
    i_key_pad ← block_sized_key xor [0x36 blockSize]   // Inner padded key

    return  hash(o_key_pad ∥ hash(i_key_pad ∥ message))

function computeBlockSizedKey is
    input:
        key:        Bytes    // Array of bytes
        hash:       Function // The hash function to use (e.g. SHA-1)
        blockSize:  Integer  // The block size of the hash function (e.g. 64 bytes for SHA-1)
 
    // Keys longer than blockSize are shortened by hashing them
    if (length(key) > blockSize) then
        key = hash(key)

    // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if (length(key) < blockSize) then
        return  Pad(key, blockSize) // Pad key with zeros to make it blockSize bytes long

    return  key

