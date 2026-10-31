import XCTest
@testable import OmniCore

final class CertificateMetadataTests: XCTestCase {
    func fixture() throws -> Data {
        try Data(contentsOf: Bundle.module.url(forResource: "synthetic-certificate", withExtension: "der", subdirectory: "Fixtures")!)
    }
    func testRealGeneratedDERValidityAndOrganizationalUnit() throws {
        let certificate = try CertificateMetadata(der: fixture())
        XCTAssertEqual(certificate.subjectOrganizationalUnits,["OMNILAB123"])
        XCTAssertFalse(certificate.hasDevelopmentMarker)
        XCTAssertEqual(certificate.validity(at:certificate.notBefore.addingTimeInterval(-1)),.notYetValid)
        XCTAssertEqual(certificate.validity(at:certificate.notBefore),.valid)
        XCTAssertEqual(certificate.validity(at:certificate.notAfter),.expired)
        XCTAssertEqual(certificate.notAfter.timeIntervalSince(certificate.notBefore),86_400)
    }
    func testRejectsTruncationIndefiniteLengthsAndTrailingData() throws {
        let valid = try fixture()
        for count in [0,1,2,10,valid.count - 1] { XCTAssertThrowsError(try CertificateMetadata(der:valid.prefix(count))) }
        XCTAssertThrowsError(try CertificateMetadata(der:valid + Data([0])))
        XCTAssertThrowsError(try CertificateMetadata(der:Data([0x30,0x80,0,0])))
        XCTAssertThrowsError(try CertificateMetadata(der:Data([0x30,0x84,0xFF,0xFF,0xFF,0xFF])))
    }
    func testRejectsInvalidCalendarDate() throws {
        var valid = try fixture()
        // UTCTime tags identify the generated validity field. Preserve lengths, invalidate month.
        guard let index = valid.indices.first(where: { $0 + 14 < valid.count && valid[$0] == 0x17 && valid[$0 + 1] == 13 }) else { return XCTFail("Expected generated UTC time") }
        valid[index + 4] = Character("1").asciiValue!; valid[index + 5] = Character("9").asciiValue!
        XCTAssertThrowsError(try CertificateMetadata(der:valid))
    }
}
