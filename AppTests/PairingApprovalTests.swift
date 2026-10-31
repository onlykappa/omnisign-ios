import XCTest
import OmniCore
@testable import OmniSign

final class PairingApprovalTests: XCTestCase {
    @MainActor func testReplacementRequiresOwnerApprovalAndCancellationPreservesPreviousBytes() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = SecureStore(service:"org.omnisign.test." + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at:directory); try? store.removeLocalItem(key:"pairing") }
        try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true)
        let previous = Data("synthetic old credential record".utf8)
        try store.save(previous,key:"pairing")
        let model = AppModel(secureStore:store,dataDirectory:directory.appendingPathComponent("state"))
        let object: [String:Any] = ["identifier":"SYNTHETIC-REMOTE", "private_key":Data(repeating:66,count:32), "public_key":Data(repeating:67,count:32)]
        let incoming = try PropertyListSerialization.data(fromPropertyList:object,format:.xml,options:0)
        let file = directory.appendingPathComponent("synthetic.plist"); try incoming.write(to:file)
        await model.importFile(file,kind:"pairing")
        XCTAssertTrue(model.pairingReplacementPending)
        XCTAssertEqual(try store.read(key:"pairing"),previous)
        model.cancelPairingReplacement()
        XCTAssertEqual(try store.read(key:"pairing"),previous)
        await model.importFile(file,kind:"pairing")
        model.approvePairingReplacement()
        XCTAssertEqual(try store.read(key:"pairing"),incoming)
        XCTAssertFalse(model.pairingReplacementPending)
        XCTAssertTrue(model.pairing.contains("unverified"))
    }
}
