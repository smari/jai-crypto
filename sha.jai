// SHA2 hash function implementation.
// Standard: https://tools.ietf.org/html/rfc4634
// Smári McCarthy, 2020-05-01

sha256sum :: (data: string) -> string {
    return sha256sum(cast([]u8)data);
}

sha256sum :: (data: []u8) -> string {
    init := {:u32:
        // Initialization vector
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    H := shabase(u32, data, init);
    digest: String_Builder;
    for 0..7 append(*digest, sprint("%", formatInt(H[it], base=16, minimum_digits=8)));
    return builder_to_string(*digest);
}

sha224sum :: (data: string) -> string {
    return sha224sum(cast([]u8)data);
}

sha224sum :: (data: []u8) -> string {
    init := {:u32:
        // Initialization vector
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    };

    H := shabase(u32, data, init);
    digest: String_Builder;
    for 0..6 append(*digest, sprint("%", formatInt(H[it], base=16, minimum_digits=8)));
    return builder_to_string(*digest);
}


sha384sum :: (data: string) -> string {
    return sha384sum(cast([]u8)data);
}

sha384sum :: (data: []u8) -> string {
    init := {:u64:
        // Initialization vector
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    };
    H := shabase(u64, data, init);
    digest: String_Builder;
    for 0..5 append(*digest, sprint("%", formatInt(H[it], base=16, minimum_digits=16)));
    return builder_to_string(*digest);
}

sha512sum :: (data: string) -> string {
    return sha512sum(cast([]u8)data);
}

sha512sum :: (data: []u8) -> string {
    init := {:u64:
        // Initialization vector
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };
    H := shabase(u64, data, init);
    digest: String_Builder;
    for 0..7 append(*digest, sprint("%", formatInt(H[it], base=16, minimum_digits=16)));
    return builder_to_string(*digest);
}



#scope_file

sha256_consts :: {:u32:
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

sha512_consts :: {:u64:
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

merkle_damgard :: (data: []u8, block_size: int) -> blocks: int, padded: []u8 #must {
    // We can allow a Merkel-Damgård construction of (roughly) any block size.
    // We only really want 64 and 128 bytes though.
    length_block := block_size >> 3;    // Byte count for input length counter.
    pad_length := block_size-length_block;

    lastblock_size := (data.count+1) % block_size; // including guard byte
    padding_bytes  := pad_length - lastblock_size;
    if lastblock_size > pad_length { padding_bytes += block_size; };

    data_padded: []u8;
    // Structure: [data][guard][padding][length]. The +1 is for the guard byte.
    data_padded.count = data.count + 1 + padding_bytes + length_block;
    data_padded.data = alloc(data_padded.count);
    memset(data_padded.data, 0, data_padded.count);
    memcpy(data_padded.data, data.data, data.count);

    data_padded[data.count] = 0b10000000; // Start padding with guard byte

    for < length_block-1..0 {
        idx := data.count+padding_bytes+(length_block-it);
        if it*8 < 64 { // TODO: This is a workaround for a pre-beta Jai issue
                       // where shifts by more than word-length loops back.
            data_padded[idx] = cast(u8) ((data.count*8)>>(it*8)) & 0xff;
        }
    }
    return blocks = data_padded.count/block_size, padded = data_padded;
}

shabase :: ($T: Type, data: []u8, init: [8]T) -> [8]T {
    // init is initialization vector.
    #if T == u32 {
        // Config for SHA256 and SHA224.
        WORD :: 32;
        BLOCK :: 64;
        BYTES :: 4;
        WSIZE :: 64;
        SHA_CONSTS :: sha256_consts;
        BSIG0 :: (x: u32) -> u32 { return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22); }
        BSIG1 :: (x: u32) -> u32 { return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25); }
        SSIG0 :: (x: u32) -> u32 { return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3); }
        SSIG1 :: (x: u32) -> u32 { return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10); }
    }
    #if T == u64 {
        // Config for SHA512 and SHA384.
        WORD :: 64;
        BLOCK :: 128;
        BYTES :: 8;
        WSIZE :: 80;
        SHA_CONSTS :: sha512_consts;
        BSIG0 :: (x: T) -> T { return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39); }
        BSIG1 :: (x: T) -> T { return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41); }
        SSIG0 :: (x: T) -> T { return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7); }
        SSIG1 :: (x: T) -> T { return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6); }
    }

    ROTR :: (x: T, n: T) -> T { return ((x >> n) | (x << (WORD-n))); }
    ROTL :: (x: T, n: T) -> T { return ((x << n) | (x >> (WORD-n))); }
    SHR  :: (x: T, n: T) -> T { return (x >> n); }
    SHL  :: (x: T, n: T) -> T { return (x << n); }
    CH :: (x: T, y: T, z: T) -> T { return (x & y) ^ ( (~x) & z); }
    MAJ :: (x: T, y: T, z: T) -> T { return (x & y) ^ (x & z) ^ (y & z); }

    M :: (i: T, t: T, data_padded: []u8) -> T {
        dp : T;
        idx := (i-1)*BLOCK+(t*BYTES);
        // TODO: Endianness. This is a slow way of enforcing big-endianness.
        //       Clean up with []u64 and data[(i-1)*16+t] with endian-enforcement.
        for 0..(BYTES-1) {
            dp |= (cast(T) data_padded[idx+xx it]) << (8*((BYTES-1)-it));
        }
        return dp;
    }

    W : [WSIZE]T;
    a, b, c, d, e, f, g, h : T;
    T1 : T = 0;
    T2 : T = 0;
    H := init;
    blocks, data_padded := merkle_damgard(data, BLOCK);

    for 1..blocks {
        // Prepare message schedule W:
        for t:0..15 {
            W[t] = M(cast(T) it, cast(T) t, data_padded);
        }
        for t:16..WSIZE-1 {
            W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
        }

        // Initialize working variables:
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];

        // Perform main hash computation:
        for t:0..WSIZE-1 {
            T1 = h + BSIG1(e) + CH(e,f,g) + SHA_CONSTS[t] + W[t];
            T2 = BSIG0(a) + MAJ(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Compute H(i):
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    free(data_padded.data);
    return H;
}
