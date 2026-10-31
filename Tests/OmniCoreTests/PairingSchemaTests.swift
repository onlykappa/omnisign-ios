import XCTest
@testable import OmniCore

final class PairingSchemaTests: XCTestCase {
    func plist(_ values: [String:Any]) throws -> Data { try PropertyListSerialization.data(fromPropertyList:values,format:.xml,options:0) }
    func lockdown() -> [String:Any] {
        var values: [String:Any] = ["HostID":"SYNTHETIC-HOST", "SystemBUID":"SYNTHETIC-BUID", "UDID":"SYNTHETIC-NOT-REAL-DEVICE", "WiFiMACAddress":"00:00:00:00:00:00"]
        for field in ["HostCertificate","HostPrivateKey","RootCertificate","RootPrivateKey","DeviceCertificate","EscrowBag"] { values[field] = Data(repeating:65,count:32) }
        return values
    }
    func remote() -> [String:Any] { ["identifier":"SYNTHETIC-REMOTE", "private_key":Data(repeating:66,count:32), "public_key":Data(repeating:67,count:32)] }
    func testSourceTracedSchemasDoNotConferCompatibility() throws {
        let legacy = try PairingSchemaInspector.inspect(plist(lockdown())), rp = try PairingSchemaInspector.inspect(plist(remote()))
        XCTAssertEqual(legacy.format,.lockdown); XCTAssertEqual(rp.format,.remotePairing)
        XCTAssertFalse(legacy.canAuthorizeTransport); XCTAssertFalse(rp.cryptographicCompatibilityVerified)
    }
    func testAmbiguousAndIncompleteInputsDoNotChooseCredentialSet() throws {
        XCTAssertThrowsError(try PairingSchemaInspector.inspect(plist(lockdown().merging(remote()) { first,_ in first })))
        var incomplete = lockdown(); incomplete.removeValue(forKey:"EscrowBag")
        XCTAssertThrowsError(try PairingSchemaInspector.inspect(plist(incomplete)))
        var wrongType = remote(); wrongType["private_key"] = "not key bytes"
        XCTAssertThrowsError(try PairingSchemaInspector.inspect(plist(wrongType)))
    }
    func testReportsCannotSerializePairingSecretsOrIdentifiers() throws {
        let report = try PairingSchemaInspector.inspect(plist(lockdown()))
        let object = try JSONSerialization.jsonObject(with:JSONEncoder().encode(report)) as! [String:Any]
        XCTAssertEqual(Set(object.keys),["format"])
        XCTAssertEqual(object["format"] as? String,"lockdown")
    }
    func testUnboundedOrNonPlistFormatsAreRejected() {
        XCTAssertThrowsError(try PairingSchemaInspector.inspect(Data(repeating:0,count:2_097_153)))
        XCTAssertThrowsError(try PairingSchemaInspector.inspect(Data("{\"private_key\":\"secret\"}".utf8)))
    }
}
