//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-01.
//

import XCTest
import Foundation
@testable import K1

final class SchnorrSignatureTests: XCTestCase {

    //    func testSchnorr() throws {
    //        let messageHex = "89D68815DDB9E5F8D7FD53B6EC096616A773B9421F6704CED36EF4E484BA0C6C5A4855C71C33A54AC82BE803E5CFD175779FC444B7E6AA9001EEFABEBC0CF99754887C7B0A27AFDDC415F8A02C5AF1EFEA26AD1E5D92B1E2"
    //        let privateKeyHex = "EDA7AFB6E3CEC979CC37BA87A09E63CAA864D0202A6BA7DF7966C012B1D92F7E"
    //        let pubHex = "024C34E2D3921D05102BF3D4EE806E188395AFD033F39D090A46A369D709797FC3"
    ////        let kHex = "63C6C74C9FD5F31B5576E47873994BB6C8724FA31EEAB7669DB915EDFDB1A23C"
    //        let rHex = "4B31EA76A9E890D533A753BEB0EE9DE1072CA5508B0DA5D45B1AA9487FA491FE"
    //        let sHex = "CC92A532CCB5172C1199178E832EA770B4BFA696034471BDC1CE23215276B109"
    //
    //        let privateKey = try K1.PrivateKey.import(rawRepresentation: Data(hex: privateKeyHex))
    //        let publicKeyImported = try K1.PublicKey.import(from: Data(hex: pubHex))
    //
    //        XCTAssertEqual(privateKey.publicKey.uncompressedRaw.hexString, publicKeyImported.uncompressedRaw.hexString)
    //
    //        let message = try Data(hex: messageHex)
    //        let signatureFromMessage = try privateKey.signature(
    //            for: message,
    //            scheme: .schnorr(nil)
    //        )
    //
    //        let sigHex = try signatureFromMessage.compactRepresentation().toHexString();
    //        XCTAssertEqual(rHex + sHex, sigHex)
    //
    //    }
        
        /// Vector 1 from:  https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
        func testSchnorr1() throws {
            let messageHex = "0000000000000000000000000000000000000000000000000000000000000000"
            let auxHex = "0000000000000000000000000000000000000000000000000000000000000000"
            let privateKeyHex = "0000000000000000000000000000000000000000000000000000000000000003"
            let pubHex = "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
            let expectedValid = true
            let expectedSignatureCompactHex = "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
            
            let privateKey = try K1.PrivateKey.import(rawRepresentation: Data(hex: privateKeyHex))
            
            XCTAssertTrue(privateKey.publicKey.uncompressedRaw.hexString.uppercased().contains(pubHex))

            let message = try Data(hex: messageHex)
            let schnorrSignature = try privateKey.schnorrSign(
                hashed: message,
                input: .init(auxilaryRandomData: Data(hex: auxHex))
            )
            
            let expectedSchnorrSig = try SchnorrSignature(rawRepresentation: Data(hex: expectedSignatureCompactHex))
            
            XCTAssertEqual(expectedSchnorrSig, schnorrSignature)
            
            let validationResult = try privateKey.publicKey.isValidSchnorrSignature(expectedSchnorrSig, hashed: message)
            XCTAssertEqual(validationResult, expectedValid)
        }
        
}
