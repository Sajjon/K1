# K1 🏔
> Safer than K2

_K1_ is Swift wrapper around [libsecp256k1 (bitcoin-core/secp256k1)](https://github.com/bitcoin-core/secp256k1), offering ECDSA, Schnorr ([BIP340][bip340]) and ECDH features.

# Features

## ECDSA Signatures

```swift
let alice = try K1.PrivateKey.generateNew()
let message = "Send Bob 3 BTC".data(using: .utf8)!
let signature = try alice.ecdsaSign(unhashed: message)
let isSignatureValid = try alice.publicKey.isValidECDSASignature(signature, unhashed: message)
assert(isSignatureValid, "Signature should be valid.")
```


## Schnorr Signatures


```swift
let alice = try K1.PrivateKey.generateNew()
let message = "Send Bob 3 BTC".data(using: .utf8)!
let signature = try alice.schnorrSign(unhashed: message)
let isSignatureValid = try alice.publicKey.isValidSchnorrSignature(signature, unhashed: message)
assert(isSignatureValid, "Signature should be valid.")
```

### Schnorr Scheme

The Schnorr signature implementation is [BIP340][bip340], since we use _libsecp256k1_ which only provides the [BIP340][bip340] Schnorr scheme. 

It is worth noting that some Schnorr implementations are incompatible with [BIP340][bip340] and thus this library, e.g. [Zilliqa's](https://github.com/Zilliqa/schnorr/blob/master/src/libSchnorr/src/Schnorr.cpp#L86-L242) ([kudelski report](https://docs.zilliqa.com/zilliqa-schnorr-audit-by-kudelski_public-release.pdf), [libsecp256k1 proposal](https://github.com/bitcoin-core/secp256k1/issues/1070), [Twitter thread](https://twitter.com/AmritKummer/status/1489645007699066886?s=20&t=eDgd5221qEPOVyStY0A8SA)).


## ECDH

```swift
let alice = try K1.PrivateKey.generateNew()
let bob = try K1.PrivateKey.generateNew()

let ab = try alice.sharedSecret(with: bob.publicKey)
let ba = try bob.sharedSecret(with: alice.publicKey)
assert(ab == ba, "Alice and Bob should be able to agree on the same secret")
```

# Alternatives

- [GigaBitcoin/secp256k1.swift](https://github.com/GigaBitcoin/secp256k1.swift) (also using `libsecp256k1`, ⚠️ possibly unsafe, ✅ Schnorr support)  
- [KevinVitale/WalletKit](https://github.com/KevinVitale/WalletKit/) (also using `libsecp256k1`, ❌ No Schnorr)  
- [leif-ibsen/SwiftECC](https://github.com/leif-ibsen/SwiftECC) (Custom ECC impl, ⚠️ possibly unsafe, ❌ No Schnorr)  
- [yenom/BitcoinKit](https://github.com/yenom/BitcoinKit) (💀 Discontinued, also using `libsecp256k1`, ❌ No Schnorr)  
- [oleganza/CoreBitcoin](https://github.com/oleganza/CoreBitcoin) (OpenSSL as ECC impl, ObjC + Swift, ⚠️ possibly unsafe, ❌ No Schnorr)  
- [Sajjon/EllipticCurveKit](https://github.com/Sajjon/EllipticCurveKit) (Custom ECC impl (mine), ☣️ unsafe, ✅ Schnorr support)  

## Non-Swift but SPM support
[greymass/secp256k1](https://github.com/greymass/secp256k1) (Fork of `libsecp256k1`)

[BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
