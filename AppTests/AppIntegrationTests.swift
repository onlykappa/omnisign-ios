import XCTest
import OmniCore
@testable import OmniSign

final class AppIntegrationTests: XCTestCase {
    @MainActor func testActualIPAImportThroughAppModelAndReload() async throws {
        let fixture = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "valid", withExtension: "ipa"))
        let model = AppModel()
        let library = try XCTUnwrap(model.library, "Protected application library must initialize on Simulator")
        let original = model.items.count
        await model.importFile(fixture, kind: "ipa")
        XCTAssertFalse(model.busy)
        XCTAssertEqual(model.items.count, original + 1)
        XCTAssertEqual(model.items.last?.main.identifier, "org.omnisign.disposable")
        XCTAssertEqual(try library.load().last?.id, model.items.last?.id)
        XCTAssertEqual(model.status, "Imported and inspected; signing unverified")
        XCTAssertEqual(model.operations.first?.result, .completed)
        XCTAssertEqual(model.operations.first?.kind, .inspection)
        XCTAssertEqual(model.operations.first?.app, model.items.last?.id)
        let journal = try XCTUnwrap(model.journal)
        let export = try await journal.exportRedacted()
        XCTAssertFalse(String(decoding: export, as: UTF8.self).contains("org.omnisign.disposable"))
    }
    func testKeychainStoreAndUpdateOnSimulator() throws {
        let store = SecureStore()
        let key = "integration-test-" + UUID().uuidString
        defer { try? store.removeLocalItem(key: key) }
        XCTAssertFalse(store.contains(key))
        try store.save(Data("synthetic first value".utf8), key: key)
        XCTAssertTrue(store.contains(key))
        try store.save(Data("synthetic replacement".utf8), key: key)
        XCTAssertTrue(store.contains(key))
        XCTAssertThrowsError(try store.inspectCertificate(Data("invalid certificate".utf8)))
    }
}
