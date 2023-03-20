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
         // Only used by tests
        .package(url: "https://github.com/filom/ASN1Decoder", from: "1.8.0"),
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
                "libsecp256k1/src/ctime_tests.c",
                
                "libsecp256k1/examples/",
                
                "libsecp256k1/autogen.sh",
                "libsecp256k1/CMakeLists.txt",
                "libsecp256k1/configure.ac",
                "libsecp256k1/COPYING",
                "libsecp256k1/libsecp256k1.pc.in",
                "libsecp256k1/Makefile.am",
                "libsecp256k1/README.md",
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
                "secp256k1",
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

