[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FSajjon%2FK1%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/Sajjon/K1)[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FSajjon%2FK1%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/Sajjon/K1)

# K1 🏔
> Safer than K2

_K1_ is Swift wrapper around [libsecp256k1 (bitcoin-core/secp256k1)][lib], offering ECDSA, Schnorr ([BIP340][bip340]) and ECDH features.

# Documentation
Read [full documentation on here][doc].

## Quick overview
The API of K1 maps almost 1:1 with Apple's [CryptoKit][ck], vendoring a set of keypairs, one per feature. E.g. in CryptoKit you have `Curve25519.KeyAgreement.PrivateKey` and `Curve25519.KeyAgreement.PublicKey` which are seperate for `Curve25519.Signing.PrivateKey` and `Curve25519.Signing.PublicKey`. 

Just like that K1 vendors these key pairs:
- `K1.KeyAgreement.PrivateKey` / `K1.KeyAgreement.PublicKey` for key agreement (ECDH)
- `K1.Schnorr.PrivateKey` / `K1.Schnorr.PublicKey` for sign / verify methods using Schnorr signature scheme
- `K1.ECDSA.Recoverable.PrivateKey` / `K1.ECDSA.Recoverable.PublicKey` for sign / verify methods using ECDSA (producing/validating signature where public key is recoverable)
- `K1.ECDSA.NonRecoverable.PrivateKey` / `K1.ECDSA.NonRecoverable.PublicKey` for sign / verify methods using ECDSA (producing/validating signature where public key is **not** recoverable)

Just like you can convert between e.g. `Curve25519.KeyAgreement.PrivateKey` and  `Curve25519.Signing.PrivateKey` back and forth using any of the initializers and serializer, you can convert between all PrivateKeys and all PublicKeys of all features in K1.

All keys can be serialized using these computed properties:

```swift
{
    var rawRepresentation: Data { get }
    var derRepresentation: Data { get }
    var pemRepresentation: String { get }
    var x963Representation: Data { get }
}
```

All keys can be deserialize using these initializer:

```swift
{
    init(rawRepresentation: some ContiguousBytes) throws
    init(derRepresentation: some RandomAccessCollection<UInt8>) throws
    init(pemRepresentation: String) throws
    init(x963Representation: some ContiguousBytes) throws
}
```

Furthermore, all PrivateKey's have these additional APIs:

```swift
{
    init()
    associatedtype PublicKey
    var publicKey: PublicKey { get }
}
```

Furthermore, all PublicKeys's have these additional APIs:

```swift
{
    init(compressedRepresentation: some ContiguousBytes) throws
    var compressedRepresentation: Data { get }
}
```


## ECDSA (Elliptic Curve Digital Signature Algorithm)

There exists two set of ECDSA key pairs:
- A key pair for signatures from which you can recover the public key, specifically: `K1.ECDSA.Recoverable.PrivateKey` and `K1.ECDSA.Recoverable.PublicKey`
- A key pair for signatures from which you can **not** recover the public key, specifically: `K1.ECDSA.NonRecoverable.PrivateKey` and `K1.ECDSA.NonRecoverable.PublicKey`

For each private key there exists two different `signature:for:options` (one taking hashed data and taking `Digest` as argument) methods and one `signature:forUnhashed:options`.

The `option` is a `K1.ECDSA.SigningOptions` struct, which by default specifies [`RFC6979`][rfc6979] deterministic signing, as per Bitcoin standard, however, you can change to use secure random nonce instead.

### NonRecoverable 

#### Sign

```swift
let alice = K1.ECDA.NonRecovarable.PrivateKey()
```

##### Hashed (Data)

```swift
let hashedMessage: Data = // from somewhere
let signature = try alice.signature(for: hashedMessage)
```

##### Digest 

```swift
let message: Data = // from somewhere
let digest = SHA256.hash(data: message)
let signature = try alice.signature(for: digest)
```

##### Hash and Sign

The `forUnhashed` will `SHA256` hash the message and then sign it. 

```swift
let message: Data = // from somewhere
let signature = try alice.signature(forUnhashed: message)
```

#### Validate

##### Hashed (Data)

```swift
let hashedMessage: Data = // from somewhere
let publicKey: K1.ECDSA.NonRecoverable.PublicKey = alice.publcKey
let signature: K1.ECDSA.NonRecoverable.Signature // from above

assert(
    publicKey.isValidSignature(signature, hashed: hashedMessage)
) // PASS
```

##### Digest

```swift
let message: Data = // from somewhere
let digest = SHA256.hash(data: message)
let signature: K1.ECDSA.NonRecoverable.Signature // from above

assert(
    publicKey.isValidSignature(signature, digest: digest)
) // PASS
```

##### Hash and Validate

```swift
let message: Data = // from somewhere
let signature: K1.ECDSA.NonRecoverable.Signature // from above

assert(
    publicKey.isValidSignature(signature, unhashed: message)
) // PASS
```


### Recoverable

All signing and validation APIs are identical to the `NonRecoverable` namespace.

```swift
let alice = K1.ECDA.Recovarable.PrivateKey()
let message: Data = // from somewhere
let digest = SHA256.hash(data: message)
let signature: K1.ECDSA.Recoverable.Signature = try alice.signature(for: digest)
let publicKey: K1.ECDSA.Recoverable.PublicKey = alice.publicKey
assert(
    publicKey.isValidSignature(signature, digest: digest)
) // PASS
```


## Schnorr Signature Scheme

### Sign

```swift
let alice = K1.Schnorr.PrivateKey()
let signature = try alice.signature(forUnhashed: message)
```

There exists other sign variants, `signature:for:options` (hashed data) and `signature:for:options` (`Digest`) if you already have a hashed message. All three variants takes a `K1.Schnorr.SigningOptions` struct where you can pass `auxiliaryRandomData` to be signed.

### Validate

```swift
let publicKey: K1.Schnorr.PublicKey = alice.publicKey
assert(publicKey.isValidSignature(signature, unhashed: message)) // PASS
```

Or alternatively `isValidSignature:digest` or `isValidSignature:hashed`.

##### Schnorr Scheme

The Schnorr signature implementation is [BIP340][bip340], since we use _libsecp256k1_ which only provides the [BIP340][bip340] Schnorr scheme. 

It is worth noting that some Schnorr implementations are incompatible with [BIP340][bip340] and thus this library, e.g. [Zilliqa's](https://github.com/Zilliqa/schnorr/blob/master/src/libSchnorr/src/Schnorr.cpp#L86-L242) ([kudelski report](https://docs.zilliqa.com/zilliqa-schnorr-audit-by-kudelski_public-release.pdf), [libsecp256k1 proposal](https://github.com/bitcoin-core/secp256k1/issues/1070), [Twitter thread](https://twitter.com/AmritKummer/status/1489645007699066886?s=20&t=eDgd5221qEPOVyStY0A8SA)).


## ECDH

This library vendors three different EC Diffie-Hellman (ECDH) key exchange functions:
1. `ASN1 x9.63` - No hash, return only the `X` coordinate of the point - `sharedSecretFromKeyAgreement:with -> SharedSecret`
2. `libsecp256k1` - SHA-256 hash the compressed point - `ecdh:with -> SharedSecret`
3. Custom - No hash, return point uncompressed - `ecdhPoint -> Data`

```swift
let alice = try K1.KeyAgreement.PrivateKey()
let bob = try K1.KeyAgreement.PrivateKey()
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

Using `libsecp256k1` default behaviour, returning a SHA-256 hash of the **compressed** point, embedded in a [`CryptoKit.SharedSecret`][ckss], which is useful since you can use `CryptoKit` key derivation functions.

```swift
let ab: CryptoKit.SharedSecret = try alice.ecdh(with: bob.publicKey) 
let ba: CryptoKit.SharedSecret = try bob.ecdh(with: alice.publicKey)
assert(ab == ba) // pass

ab.withUnsafeBytes {
    assert(Data($0).count == 32) // pass
}
```

### Custom ECDH

Returns an entire uncompressed EC point, without hashing it. Might be useful if you wanna construct your own cryptographic functions, e.g. some custom ECIES.

```swift
let ab: Data = try alice.ecdhPoint(with: bob.publicKey) 
let ba: Data = try bob.ecdhPoint(with: alice.publicKey)
assert(ab == ba) // pass

assert(ab.count == 65) // pass
```


# Acknowledgements
`K1` is a Swift wrapper around [libsecp256k1][lib], so this library would not exist without the Bitcoin Core developers. Massive thank you for a wonderful library! I've included it as a submodule, without any changes to the code, i.e. with copyright headers in files intact.

`K1` uses some code from [`swift-crypto`][swc], which has been copied over with relevant copyright header. Since [`swift-crypto`][swc] is licensed under [Apache](https://github.com/apple/swift-crypto/blob/main/LICENSE.txt), so is this library.

# Development

Stand in root and run

```sh
./scripts/build.sh
```

To clone the dependency [libsecp256k1][lib], using commit [427bc3cdcfbc74778070494daab1ae5108c71368](https://github.com/bitcoin-core/secp256k1/commit/427bc3cdcfbc74778070494daab1ae5108c71368) (semver 0.3.0)


## `gyb`

Some of the files in this project are autogenerated (metaprogramming) using the Swift Utils tools called [gyb](https://github.com/apple/swift/blob/main/utils/gyb.py) (_"generate your boilerplate"_). `gyb` is included in [`./scripts/gyb`](scripts/gyb).

`gyb` will generate some `Foobar.swift` Swift file from some `Foobar.swift.gyb` _template_ file. **You should not edit `Foobar.swift` directly**, since all manual edits in that generated file will be overwritten the next time `gyb` is run.

You run `gyb` for a single file like so:

```bash
./scripts/gyb --line-directive "" Sources/Foobar.swift.gyb -o Sources/Foobar.swift
```

More conveniently you can run the bash script `./scripts/generate_boilerplate_files_with_gyb.sh` to generate all Swift files from their corresponding gyb template.

**If you add a new `.gyb` file, you should append a `// MARK: - Generated file, do NOT edit` warning** inside it, e.g.

```swift
// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.
```


# Alternatives

- [GigaBitcoin/secp256k1.swift](https://github.com/GigaBitcoin/secp256k1.swift) (also using `libsecp256k1`, ⚠️ possibly unsafe, ✅ Schnorr support)  
- [KevinVitale/WalletKit](https://github.com/KevinVitale/WalletKit/) (also using `libsecp256k1`, ❌ No Schnorr)  
- [leif-ibsen/SwiftECC](https://github.com/leif-ibsen/SwiftECC) (Custom ECC impl, ⚠️ possibly unsafe, ❌ No Schnorr)  
- [yenom/BitcoinKit](https://github.com/yenom/BitcoinKit) (💀 Discontinued, also using `libsecp256k1`, ❌ No Schnorr)  
- [oleganza/CoreBitcoin](https://github.com/oleganza/CoreBitcoin) (OpenSSL as ECC impl, ObjC + Swift, ⚠️ possibly unsafe, ❌ No Schnorr)  
- [Sajjon/EllipticCurveKit](https://github.com/Sajjon/EllipticCurveKit) (Custom ECC impl (mine), ☣️ unsafe, ✅ Schnorr support)

[doc]: https://swiftpackageindex.com/sajjon/k1/documentation/k1/k1/ecdsa
[ck]: https://developer.apple.com/documentation/cryptokit
[BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[lib]: https://github.com/bitcoin-core/secp256k1
[x963]: https://webstore.ansi.org/standards/ascx9/ansix9632011r2017
[ckss]: https://developer.apple.com/documentation/cryptokit/sharedsecret
[swc]: https://github.com/apple/swift-crypto
[rfc6979]: https://www.rfc-editor.org/rfc/rfc6979
[mall]: https://en.bitcoin.it/wiki/Transaction_malleability
