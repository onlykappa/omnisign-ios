import XCTest
import Security
import OmniCore
@testable import OmniSign

final class AppleDevelopmentTrustTests: XCTestCase {
    func fixture(_ name: String, _ type: String) throws -> Data {
        try Data(contentsOf:XCTUnwrap(Bundle(for:Self.self).url(forResource:name,withExtension:type)))
    }
    func testOfficialPublicRootMatchesPinButIsNotDevelopmentIdentity() throws {
        let data = try fixture("AppleRootCA-G3","cer")
        XCTAssertTrue(AppleDevelopmentTrust.isKnownAppleRoot(data))
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil,data as CFData))
        let assessment = try AppleDevelopmentTrust.inspect(certificate)
        XCTAssertEqual(assessment.state,.blocked)
        XCTAssertFalse(assessment.canAuthorizeSigning)
    }
    func testSelfSignedDevelopmentMarkerDoesNotEstablishAppleTrust() throws {
        let data = try fixture("synthetic-developer-marker","der")
        XCTAssertTrue(try CertificateMetadata(der:data).hasDevelopmentMarker)
        XCTAssertFalse(AppleDevelopmentTrust.isKnownAppleRoot(data))
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil,data as CFData))
        let metadata = try CertificateMetadata(der:data)
        let assessment = try AppleDevelopmentTrust.inspect(certificate,at:metadata.notBefore.addingTimeInterval(1))
        XCTAssertEqual(assessment.state,.blocked)
        XCTAssertFalse(assessment.canAuthorizeSigning)
        XCTAssertTrue([AppleTrustBlocker.untrustedOrIncompleteChain,.nonAppleRoot].contains(try XCTUnwrap(assessment.blocker)))
    }
}
