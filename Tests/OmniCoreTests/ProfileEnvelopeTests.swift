import XCTest
@testable import OmniCore

final class ProfileEnvelopeTests: XCTestCase {
    func fixture() throws -> Data {
        try Data(contentsOf:Bundle.module.url(forResource:"synthetic-profile",withExtension:"cms",subdirectory:"Fixtures")!)
    }
    func testGeneratedNonAppleCMSIsInspectedButNeverTrusted() throws {
        let envelope = try ProfileEnvelope(cms:fixture())
        XCTAssertEqual(envelope.profileName,"OmniSign Synthetic Profile")
        XCTAssertEqual(envelope.summary.team,"OMNILAB123")
        XCTAssertEqual(envelope.summary.deviceCount,1)
        XCTAssertEqual(envelope.signerCount,1)
        XCTAssertFalse(envelope.cmsSignatureVerified)
        XCTAssertThrowsError(try envelope.requireTrustedForSigning())
    }
    func testExpiredProfileRemainsInspectableButCannotPassTimePolicy() throws {
        let now = Date(timeIntervalSince1970:2_000_000_000)
        let envelope = try ProfileEnvelope(cms:fixture(),now:now)
        XCTAssertFalse(envelope.summary.permits(bundleID:"org.omnisign.lab",team:"OMNILAB123",now:now))
        XCTAssertFalse(envelope.cmsSignatureVerified)
    }
    func testRejectsDetachedRandomTruncatedAndTrailingPayloads() throws {
        let good = try fixture()
        for bad in [Data(),Data("<plist/>".utf8),Data(good.prefix(100)),good + Data([0]),Data([0x30,0x80,0,0])] {
            XCTAssertThrowsError(try ProfileEnvelope(cms:bad))
        }
    }
    func testDecodedProfileRejectsMalformedTimeTypesAndOversizedInput() throws {
        let object: [String: Any] = ["TeamIdentifier":["TEAM"], "Entitlements":["application-identifier":"TEAM.org.test"], "ExpirationDate":Date.distantFuture, "CreationDate":"not a Date"]
        let plist = try PropertyListSerialization.data(fromPropertyList:object,format:.xml,options:0)
        XCTAssertThrowsError(try ProfileSummary(decodedPlist:plist,allowExpiredForInspection:true))
        XCTAssertThrowsError(try ProfileSummary(decodedPlist:Data(repeating:0,count:1_048_577)))
    }
    func testNotYetValidProfileFailsUseTimePolicy() throws {
        let now = Date(timeIntervalSince1970:1_000_000)
        let envelope = try ProfileEnvelope(cms:fixture(),now:now)
        XCTAssertFalse(envelope.summary.permits(bundleID:"org.omnisign.lab",team:"OMNILAB123",now:now))
    }
}
