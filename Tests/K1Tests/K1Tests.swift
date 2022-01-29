import XCTest
import K1

final class K1Tests: XCTestCase {

    func testSecp256k1Vector1() throws {
        try verifyRFC6979WithSignature(
            key: "CCA9FBCC1B41E5A95D369EAA6DDCFF73B61A4EFAA279CFC6567E8DAA39CBAF50",
            message: "sample",
            expected: (
                k: "2df40ca70e639d89528a6b670d9d48d9165fdc0febc0974056bdce192b8e16a3",
                r: "af340daf02cc15c8d5d08d7735dfe6b98a474ed373bdb5fbecf7571be52b3842",
                s: "5009fb27f37034a9b24b707b7c6b79ca23ddef9e25f7282e8a797efe53a8f124",
                der: "3045022100af340daf02cc15c8d5d08d7735dfe6b98a474ed373bdb5fbecf7571be52b384202205009fb27f37034a9b24b707b7c6b79ca23ddef9e25f7282e8a797efe53a8f124"
            )
        )
    }

    func testSecp256k1Vector2() throws {
        try verifyRFC6979WithSignature(
            key: "0000000000000000000000000000000000000000000000000000000000000001",
            message: "Satoshi Nakamoto",
            expected: (
                k: "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15",
                r: "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8",
                s: "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5",
                der: "3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
            )
        )
    }

    func testSecp256k1Vector3() throws {
        try verifyRFC6979WithSignature(
            key: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            message: "Satoshi Nakamoto",
            expected: (
                k: "33a19b60e25fb6f4435af53a3d42d493644827367e6453928554f43e49aa6f90",
                r: "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d0",
                s: "6b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5",
                der: "3045022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d002206b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"
            )
        )
    }

    func testSecp256k1Vector4() throws {
        try verifyRFC6979WithSignature(
            key: "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
            message: "Alan Turing",
            expected: (
                k: "525a82b70e67874398067543fd84c83d30c175fdc45fdeee082fe13b1d7cfdf1",
                r: "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c",
                s: "58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea",
                der: "304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"
            )
        )
    }

    func testSecp256k1Vector5() throws {
        try verifyRFC6979WithSignature(
            key: "0000000000000000000000000000000000000000000000000000000000000001",
            message: "All those moments will be lost in time, like tears in rain. Time to die...",
            expected: (
                k: "38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3",
                r: "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b",
                s: "547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21",
                der: "30450221008600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b0220547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"
            )
        )
    }

    func testSecp256k1Vector6() throws {
        try verifyRFC6979WithSignature(
            key: "e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2",
            message: "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
            expected: (
                k: "1f4b84c23a86a221d233f2521be018d9318639d5b8bbd6374a8a59232d16ad3d",
                r: "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b",
                s: "279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6",
                der: "3045022100b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b0220279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6"
            )
        )
    }
}
 
extension XCTestCase {
    func verifyRFC6979WithSignature(
        key privateKeyHex: String,
        message messageToHash: String,
        expected: (k: String, r: String, s: String, der: String),
        line: UInt = #line
    ) throws {
        try verifyRFC6979(
            key: privateKeyHex,
            message: messageToHash,
            expected: (k: expected.k, r: expected.r, s: expected.s, der: expected.der),
            line: line
        )
    }
    
    func verifyRFC6979(
        key privateKeyHex: String,
        message messageToHash: String,
        expected: (k: String, r: String?, s: String?, der: String?),
        line: UInt
    ) throws {

        if expected.r == nil && expected.s == nil && expected.der == nil {
            XCTFail("Cannot run test if no expected signature data was provided", line: line)
            return
        }

        let privateKey = try K1.PrivateKey.import(rawRepresentation: Data.init(hex: privateKeyHex))
        let publicKey = privateKey.publicKey
        let message = messageToHash.data(using: .utf8)!
        let signatureFromMessage = try privateKey.signature(for: message)  //AnyKeySigner<ECDSA<C>>.sign(message, using: keyPair)
        XCTAssertTrue(try publicKey.isValidSignature(signatureFromMessage, for: message))

        if let expectedRHex = expected.r,  let expectedSHex = expected.s  {
            let sigHex = try signatureFromMessage.compactRepresentation().toHexString()
            XCTAssertEqual(expectedRHex + expectedSHex, sigHex, line: line)
        }
  
        if let expectedDER = expected.der {
            let der = try signatureFromMessage.derRepresentation().toHexString()
            XCTAssertEqual(expectedDER, der, line: line)
        }
    }    
}


public extension Data {
    init(hex: String) throws {
       try self.init(Array<UInt8>(hex: hex))
    }
    
    var bytes: Array<UInt8> {
        Array(self)
    }
    
    func toHexString() -> String {
        self.bytes.toHexString()
    }
}

extension Array {
    init(reserveCapacity: Int) {
        self = Array<Element>()
        self.reserveCapacity(reserveCapacity)
    }
    
    var slice: ArraySlice<Element> {
        self[self.startIndex ..< self.endIndex]
    }
}

extension String {
    func byteArray() throws -> [UInt8] {
        try Array(hex: self)
    }
}

enum BytesError: Swift.Error {
    case stringNotValidHex
}

extension Array where Element == UInt8 {
    public init(hex: String) throws {
        self.init(reserveCapacity: hex.unicodeScalars.lazy.underestimatedCount)
        var buffer: UInt8?
        var skip = hex.hasPrefix("0x") ? 2 : 0
        for char in hex.unicodeScalars.lazy {
            guard skip == 0 else {
                skip -= 1
                continue
            }
            guard char.value >= 48 && char.value <= 102 else {
                throw BytesError.stringNotValidHex
            }
            let v: UInt8
            let c: UInt8 = UInt8(char.value)
            switch c {
            case let c where c <= 57:
                v = c - 48
            case let c where c >= 65 && c <= 70:
                v = c - 55
            case let c where c >= 97:
                v = c - 87
            default:
                removeAll()
                return
            }
            if let b = buffer {
                append(b << 4 | v)
                buffer = nil
            } else {
                buffer = v
            }
        }
        if let b = buffer {
            append(b)
        }
    }
    
    public func toHexString() -> String {
        `lazy`.reduce(into: "") {
            var s = String($1, radix: 16)
            if s.count == 1 {
                s = "0" + s
            }
            $0 += s
        }
    }
}
