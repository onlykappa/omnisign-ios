// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import XCTest
import CodeSignKit
import DisposableSigningSupport

final class SyntheticIdentityTests: XCTestCase {
    func testGeneratedSyntheticIdentityIsSelfIssuedAndMatchesAccessibleKey() throws {
        let identity = try SyntheticIdentityFactory.generate()
        let parsed = try PKCS12Parser(p12Data:identity.ephemeralPKCS12,allowUnauthenticatedSynthetic:true)
        let certificate = try XCTUnwrap(parsed.leafCertificate)
        XCTAssertEqual(certificate.commonName,"OmniSign Disposable Lab")
        XCTAssertEqual(certificate.organizationalUnit,"OMNILAB123")
        XCTAssertEqual(certificate.issuerDER,certificate.subjectDER)
        XCTAssertEqual(certificate.rawDER,identity.certificateDER)
        XCTAssertNotNil(parsed.rsaPrivateKey)
        XCTAssertEqual(parsed.rsaPrivateKey?.publicKey.derRepresentation,certificate.subjectPublicKeyInfoDER)
    }
    func testUnimplementedPFXEncryptionCannotSilentlyIgnorePassword() throws {
        XCTAssertThrowsError(try PKCS12Builder.build(certificateDER:Data(),privateKeyDER:nil,password:UUID().uuidString))
    }
}
