# Jai Cryptographic Primitives Library

This is very rudimentary native cryptography library for Jai.

Currently it supports only the SHA-2 family of hash functions, but more will be
added later. See *Features* below.

## Usage

Easiest is to load it into your program like so:

```
#load "jai-crypto/module.jai";
```

But if you want to provide it as a local module, you can put it in Jai's `modules/` directory
(or better yet, symlink it in there). I call it `Crypto` there. Then you can do:

```
#import "Crypto";
```

Beware, if you do this, that at some point Jai will probably have a library called `Crypto`,
that may or may not be based on this one. You may end up confusing yourself or others!

# Features

## Hash functions

 * `sha224sum :: (string) -> string`
 * `sha224sum :: ([]u8) -> string`
 * `sha256sum :: (string) -> string`
 * `sha256sum :: ([]u8) -> string`
 * `sha384sum :: (string) -> string`
 * `sha384sum :: ([]u8) -> string`
 * `sha512sum :: (string) -> string`
 * `sha512sum :: ([]u8) -> string`
