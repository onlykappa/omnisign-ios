// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import XCTest
@testable import IndependentCMSVerifier

final class CMSVerifierTests: XCTestCase {
    func data(_ name: String, _ type: String) throws -> Data { try Data(contentsOf:Bundle.module.url(forResource:name,withExtension:type,subdirectory:"Fixtures")!) }
    func testIndependentOpenSSLVectorWithoutTrustClaim() throws {
        let result = try IndependentCMSVerifier.verify(signature:data("synthetic-signature","cms"),detachedContent:data("content","bin"))
        XCTAssertTrue(result.signatureMathematicallyVerified)
        XCTAssertFalse(result.appleTrustVerified); XCTAssertFalse(result.certificateTimeChecked); XCTAssertFalse(result.canAuthorizeInstallation)
    }
    func testContentTamperingFailsCryptographicBinding() throws {
        XCTAssertThrowsError(try IndependentCMSVerifier.verify(signature:data("synthetic-signature","cms"),detachedContent:Data("tampered".utf8)))
    }
    func testSignatureTamperingFailsMathematicalVerification() throws {
        var signature = try data("synthetic-signature","cms"); signature[signature.count - 1] ^= 1
        XCTAssertThrowsError(try IndependentCMSVerifier.verify(signature:signature,detachedContent:data("content","bin")))
    }
    func testMalformedBoundedDERIsRejected() throws {
        let original = try data("synthetic-signature","cms"), content = try data("content","bin")
        for value in [Data(),Data([0x30,0x80,0,0]),Data(original.prefix(100)),original + Data([0])] {
            XCTAssertThrowsError(try IndependentCMSVerifier.verify(signature:value,detachedContent:content))
        }
    }
}
