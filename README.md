# K1 🏔
> Safer than K2

_K1_ is Swift wrapper around [libsecp256k1 (bitcoin-core/secp256k1)](https://github.com/bitcoin-core/secp256k1), offering ECDSA, Schnorr and ECDH features.

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

## ECDH

```swift
let alice = try K1.PrivateKey.generateNew()
let bob = try K1.PrivateKey.generateNew()

let ab = try alice.sharedSecret(with: bob.publicKey)
let ba = try bob.sharedSecret(with: alice.publicKey)
assert(ab == ba, "Alice and Bob should be able to agree on the same secret")
```

# Alternatives

[GigaBitcoin/secp256k1.swift](https://github.com/GigaBitcoin/secp256k1.swift) (also using `libsecp256k1`, ❌ No Schnorr)
[KevinVitale/WalletKit](https://github.com/KevinVitale/WalletKit/) (also using `libsecp256k1`, ❌ No Schnorr)
[yenom/BitcoinKit](https://github.com/yenom/BitcoinKit) (💀 Discontinued, also using `libsecp256k1`, ❌ No Schnorr)
[oleganza/CoreBitcoin](https://github.com/oleganza/CoreBitcoin) (ObjC + Swift, ❌ No Schnorr)
[Sajjon/EllipticCurveKit](https://github.com/Sajjon/EllipticCurveKit) (mine, ☣️ unsafe, ✅ Schnorr support)

## Non-Swift but SPM support
[greymass/secp256k1](https://github.com/greymass/secp256k1) (Fork of `libsecp256k1`)
