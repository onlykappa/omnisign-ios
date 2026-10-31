import XCTest
@testable import OmniCore

final class CoreTests: XCTestCase {
    func fixture(_ name: String) -> URL { Bundle.module.url(forResource: name, withExtension: "ipa", subdirectory: "Fixtures")! }
    func testMetadataAndNestedPlan() throws {
        let result = try IPAInspector().inspect(fixture("valid"))
        XCTAssertEqual(result.main.identifier, "org.omnisign.disposable")
        XCTAssertEqual(result.main.version, "1.2")
        XCTAssertEqual(result.bundles.count, 3)
        XCTAssertEqual(result.nativeLibraries.count, 1)
        XCTAssertEqual(result.signingOrder.last, result.main.path)
        XCTAssertFalse(result.warnings.isEmpty)
    }
    func testHostileArchives() {
        for name in ["traversal", "absolute", "backslash", "collision", "symlink", "corrupt", "multiple", "missing", "badmagic", "missingframework", "oversize"] {
            XCTAssertThrowsError(try IPAInspector().inspect(fixture(name)), name)
        }
    }
    func testUnsafePaths() {
        for name in ["", "a//b", "a/../b", "a/./b", "C:/a", "a\u{0}b"] { XCTAssertThrowsError(try IPAInspector.validatePath(name)) }
    }
    func testAtomicImportAndPersistence() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try Library(directory: directory)
        let result = try store.importIPA(fixture("valid"))
        XCTAssertEqual(try Library(directory: directory).load().first?.id, result.id)
        XCTAssertThrowsError(try store.importIPA(fixture("traversal")))
        XCTAssertEqual(try store.load().count, 1)
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: directory.path).contains { $0.hasSuffix(".part") })
    }
    func profile(expiry: Date = Date().addingTimeInterval(3600), app: String = "TEAM.org.test") throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: ["TeamIdentifier":["TEAM"], "ExpirationDate":expiry, "Entitlements":["application-identifier":app], "ProvisionedDevices":["synthetic"]], format: .xml, options: 0)
    }
    func testProvisioningParsingAndExpiry() throws {
        let p = try ProfileSummary(decodedPlist: profile())
        XCTAssertTrue(p.permits(bundleID: "org.test", team: "TEAM"))
        XCTAssertFalse(p.permits(bundleID: "org.test2", team: "TEAM"))
        XCTAssertFalse(p.permits(bundleID: "org.test", team: "OTHER"))
        XCTAssertThrowsError(try ProfileSummary(decodedPlist: profile(expiry: Date.distantPast)))
        XCTAssertThrowsError(try ProfileSummary(decodedPlist: profile(app: "OTHER.org.test")))
        XCTAssertThrowsError(try ProfileSummary(decodedPlist: Data("invalid CMS".utf8)))
    }
    func testEntitlementsFailClosed() {
        XCTAssertTrue(EntitlementPolicy.compatible(requested: ["x":"y"], allowed: ["x":"y"]))
        XCTAssertFalse(EntitlementPolicy.compatible(requested: ["x":"y"], allowed: ["x":"*"]))
    }
    func testInstallationPreflight() {
        XCTAssertThrowsError(try InstallationPreflight.check(oldBundle:"org.a", newBundle:"org.b", oldTeam:"T", newTeam:"T", signatureVerified:true, transportVerified:true))
        XCTAssertThrowsError(try InstallationPreflight.check(oldBundle:"org.a", newBundle:"org.a", oldTeam:"T", newTeam:"T", signatureVerified:false, transportVerified:true))
    }
    func testNoOperationCanSucceed() async {
        for kind in OperationKind.allCases {
            do { try await ExperimentalEngine().perform(kind) } catch { XCTAssertEqual(error as? OmniError, .unavailable) }
        }
    }
    func testRecoveryBoundAndRateLimits() {
        var b = RecoveryBudget()
        XCTAssertFalse(b.permit(strategy:"auth", category:.authentication))
        XCTAssertFalse(b.permit(strategy:"network", category:.transport, httpStatus:503))
        XCTAssertFalse(b.permit(strategy:"network", category:.transport, securityRestriction:true))
        for i in 0..<5 { XCTAssertTrue(b.permit(strategy:"\(i)", category:.transport)) }
        XCTAssertFalse(b.permit(strategy:"sixth", category:.transport))
        XCTAssertFalse(b.permit(strategy:"0", category:.transport))
    }
    func testErrorContextContainsOnlyAllowlistedValues() throws {
        for code in [-80045,-80046,7460] {
            let d = Diagnostic(category:.provisioning, code:code)
            XCTAssertEqual(d.category,.provisioning)
            XCTAssertEqual(d.code,code)
            let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(d)) as! [String:Any]
            XCTAssertEqual(Set(object.keys), Set(["id","date","category","code","operation","message"]))
        }
        XCTAssertEqual(Diagnostic(category:.transport,httpStatus:503).category,.authentication)
    }
    func testPairingRejectsIncompleteAndArbitraryData() throws {
        XCTAssertThrowsError(try PairingInspector.validate(Data("secret".utf8)))
        let data = try PropertyListSerialization.data(fromPropertyList: ["HostID":"synthetic", "SystemBUID":"synthetic"], format:.xml, options:0)
        XCTAssertThrowsError(try PairingInspector.validate(data))
    }
}
