

#load "../hmac.jai";
#load "../sha256.jai";
#load "../md5.jai";

main :: () {
    assert(hmac_md5("key", "The quick brown fox jumps over the lazy dog")    == "80070713463e7749b90c2dc24911e275");
    assert(hmac_sha1("key", "The quick brown fox jumps over the lazy dog")   == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
    assert(hmac_sha256("key", "The quick brown fox jumps over the lazy dog") == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    assert(hmac_sha512("key", "The quick brown fox jumps over the lazy dog") == "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a");
}