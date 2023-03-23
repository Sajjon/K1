# K1 🏔
> Safer than K2

_K1_ is Swift wrapper around [libsecp256k1 (bitcoin-core/secp256k1)][lib], offering ECDSA, Schnorr ([BIP340][bip340]) and ECDH features.

# Features

## ECDSA Signatures

```swift
let alice = try K1.PrivateKey()
let message = "Send Bob 3 BTC".data(using: .utf8)!
let signature = try alice.ecdsaSign(unhashed: message)
let isSignatureValid = try alice.publicKey.isValidECDSASignature(signature, unhashed: message)
assert(isSignatureValid, "Signature should be valid.")
```


## Schnorr Signatures


```swift
let alice = try K1.PrivateKey()
let message = "Send Bob 3 BTC".data(using: .utf8)!
let signature = try alice.schnorrSign(unhashed: message)
let isSignatureValid = try alice.publicKey.isValidSchnorrSignature(signature, unhashed: message)
assert(isSignatureValid, "Signature should be valid.")
```

### Schnorr Scheme

The Schnorr signature implementation is [BIP340][bip340], since we use _libsecp256k1_ which only provides the [BIP340][bip340] Schnorr scheme. 

It is worth noting that some Schnorr implementations are incompatible with [BIP340][bip340] and thus this library, e.g. [Zilliqa's](https://github.com/Zilliqa/schnorr/blob/master/src/libSchnorr/src/Schnorr.cpp#L86-L242) ([kudelski report](https://docs.zilliqa.com/zilliqa-schnorr-audit-by-kudelski_public-release.pdf), [libsecp256k1 proposal](https://github.com/bitcoin-core/secp256k1/issues/1070), [Twitter thread](https://twitter.com/AmritKummer/status/1489645007699066886?s=20&t=eDgd5221qEPOVyStY0A8SA)).


## ECDH

This library vendors three different EC Diffie-Hellman (ECDH) key exchange functions:
1. `ASN1 x9.63` - No hash, return only the `X` coordinate of the point - `sharedSecretFromKeyAgreement -> SharedSecret`
2. `libsecp256k1` - SHA-256 hash the compressed point - `ecdh -> Data`
3. Custom - No hash, return point uncompressed - `ecdhPoint -> Data`

```swift
let alice = try K1.PrivateKey()
let bob = try K1.PrivateKey()
```

### `ASN1 x9.63` ECDH
Returning only the `X` coordinate of the point, following [ANSI X9.63][x963] standards, embedded in a [`CryptoKit.SharedSecret`][ckss], which is useful since you can use `CryptoKit` key derivation functions on this SharedSecret, e.g. [`x963DerivedSymmetricKey`](https://developer.apple.com/documentation/cryptokit/sharedsecret/x963derivedsymmetrickey(using:sharedinfo:outputbytecount:)) or [`hkdfDerivedSymmetricKey`](https://developer.apple.com/documentation/cryptokit/sharedsecret/hkdfderivedsymmetrickey(using:salt:sharedinfo:outputbytecount:)).

You can retrieve the `X` coordinate as raw data using `withUnsafeBytes` if you need to.

```swift
let ab: CryptoKit.SharedSecret = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey) 
let ba: CryptoKit.SharedSecret = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)

assert(ab == ba) // pass

ab.withUnsafeBytes {
    assert(Data($0).count == 32) // pass
}
```

### `libsecp256k1` ECDH

Using `libsecp256k1` default behaviour, returning a SHA-256 hash of the **compressed** point.

```swift
let ab: Data = try alice.ecdh(with: bob.publicKey) 
let ba: Data = try bob.ecdh(with: alice.publicKey)
assert(ab == ba) // pass

ab.withUnsafeBytes {
    assert(Data($0).count == 32) // pass
}
```

### Custom ECDH

Returns an entire uncompresed EC point, without hashing it. Might be useful if you wanna construct your own cryptographic functions, e.g. some custom ECIES.

```swift
let ab: Data = try alice.ecdhPoint(with: bob.publicKey) 
let ba: Data = try bob.ecdhPoint(with: alice.publicKey)
assert(ab == ba) // pass

assert(ab.count == 65) // pass
```

# Acknowledgements
`K1` is a Swift wrapper around [libsecp256k1][lib], so this library would not exist without the Bitcoin Core developers. Massive thank you for a wonder ful library! I've included it as a submodule, without any changes to the code, i.e. with copyright headers in files intact.

`K1` uses some code from [`swift-crypto`][swc], which has been copied over with relevant copyright header. Since [`swift-crypto`][swc] is licensed under [Apache](https://github.com/apple/swift-crypto/blob/main/LICENSE.txt), so is this library.

# Development

Stand in root and run

```sh
./scripts/build.sh
```

To clone the dependency [libsecp256k1][lib], using commit [427bc3cdcfbc74778070494daab1ae5108c71368](https://github.com/bitcoin-core/secp256k1/commit/427bc3cdcfbc74778070494daab1ae5108c71368) (semver 0.3.0)

# Alternatives

- [GigaBitcoin/secp256k1.swift](https://github.com/GigaBitcoin/secp256k1.swift) (also using `libsecp256k1`, ⚠️ possibly unsafe, ✅ Schnorr support)  
- [KevinVitale/WalletKit](https://github.com/KevinVitale/WalletKit/) (also using `libsecp256k1`, ❌ No Schnorr)  
- [leif-ibsen/SwiftECC](https://github.com/leif-ibsen/SwiftECC) (Custom ECC impl, ⚠️ possibly unsafe, ❌ No Schnorr)  
- [yenom/BitcoinKit](https://github.com/yenom/BitcoinKit) (💀 Discontinued, also using `libsecp256k1`, ❌ No Schnorr)  
- [oleganza/CoreBitcoin](https://github.com/oleganza/CoreBitcoin) (OpenSSL as ECC impl, ObjC + Swift, ⚠️ possibly unsafe, ❌ No Schnorr)  
- [Sajjon/EllipticCurveKit](https://github.com/Sajjon/EllipticCurveKit) (Custom ECC impl (mine), ☣️ unsafe, ✅ Schnorr support)


[BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[lib]: https://github.com/bitcoin-core/secp256k1
[x963]: https://webstore.ansi.org/standards/ascx9/ansix9632011r2017
[ckss]: https://developer.apple.com/documentation/cryptokit/sharedsecret
[swc]: https://github.com/apple/swift-crypto
