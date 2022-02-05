// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "K1",
    
    platforms: [
      .macOS(.v11),
      .iOS(.v13),
    ],

    products: [
        .library(
            name: "K1",
            targets: [
                "K1"
            ]
        ),
    ],

    dependencies: [
        // Primarily used for SHA256 digests.
        .package(url: "https://github.com/apple/swift-crypto.git", "2.0.0" ..< "3.0.0"),
        
        // Used once in source, to check if imported private key is in bounds: [1, Curve.order]
        // seems prudent to use BigInt rather than implement `Comparable` for `Data`.
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
        
        // Only used by tests
        .package(url: "https://github.com/filom/ASN1Decoder", .branch("master"))
    ],

    targets: [
        
        // Target `libsecp256k1` https://github.com/bitcoin-core/secp256k1
        .target(
            name: "secp256k1",
            exclude: [
                "libsecp256k1/src/asm",
                "libsecp256k1/src/bench.c",
                "libsecp256k1/src/bench_ecmult.c",
                "libsecp256k1/src/bench_internal.c",
                "libsecp256k1/src/modules/extrakeys/tests_impl.h",
                "libsecp256k1/src/modules/schnorrsig/tests_impl.h",
                "libsecp256k1/src/precompute_ecmult.c",
                "libsecp256k1/src/precompute_ecmult_gen.c",
                "libsecp256k1/src/tests_exhaustive.c",
                "libsecp256k1/src/tests.c",
                "libsecp256k1/src/valgrind_ctime_test.c",
                
                "libsecp256k1/configure.ac",
                "libsecp256k1/src/modules/extrakeys/Makefile.am.include",
                "libsecp256k1/src/modules/ecdh/Makefile.am.include",
                "libsecp256k1/src/modules/schnorrsig/Makefile.am.include",
                "libsecp256k1/src/modules/recovery/Makefile.am.include",
                "libsecp256k1/autogen.sh",
                "libsecp256k1/libsecp256k1.pc.in",
                "libsecp256k1/doc",
                "libsecp256k1/contrib",
                "libsecp256k1/ci",
                "libsecp256k1/sage",
                "libsecp256k1/build-aux",
                "libsecp256k1/README.md",
                "libsecp256k1/Makefile.am",
                "libsecp256k1/COPYING",
                "libsecp256k1/SECURITY.md"
            ],
            cSettings: [
                // Basic config values that are universal and require no dependencies.
                // https://github.com/bitcoin-core/secp256k1/blob/master/src/basic-config.h#L12-L13
                .define("ECMULT_WINDOW_SIZE", to: "15"),
                .define("ECMULT_GEN_PREC_BITS", to: "4"),

                // Enable modules in secp256k1.
                // See bottom of: Sources/secp256k1/libsecp256k1/src/secp256k1.c
                // For list
                .define("ENABLE_MODULE_ECDH"),
                .define("ENABLE_MODULE_RECOVERY"),
                .define("ENABLE_MODULE_SCHNORRSIG"),
                .define("ENABLE_MODULE_EXTRAKEYS"),
            ]
        ),

        .target(
            name: "K1",
            dependencies: [
                
                // ECDSA, Schnorr, ECDH etc.
                "secp256k1",

                // Curve.order bounds check for private key
                "BigInt",

                // SHA256 digests
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),

        .testTarget(
            name: "K1Tests",
            dependencies: [
                "K1",
                
                // DER decoding of public keys from test vectors
                "ASN1Decoder"
            ],
            resources: [
                .process("TestVectors/"),
            ]
        ),
    ]
)

