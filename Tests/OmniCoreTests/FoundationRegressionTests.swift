import XCTest
@testable import OmniCore

final class FoundationRegressionTests: XCTestCase {
    func fixture() -> URL { Bundle.module.url(forResource: "valid", withExtension: "ipa", subdirectory: "Fixtures")! }
    func directory() throws -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }
    func testCorruptMetadataFailsClosedWithoutOverwriting() throws {
        let d = try directory(); defer { try? FileManager.default.removeItem(at: d) }
        let library = try Library(directory: d)
        let item = try library.importIPA(fixture())
        let index = d.appendingPathComponent("index.json")
        var objects = try JSONSerialization.jsonObject(with: Data(contentsOf: index)) as! [[String: Any]]
        objects[0]["bundles"] = []
        let corrupt = try JSONSerialization.data(withJSONObject: objects)
        try corrupt.write(to: index)
        XCTAssertThrowsError(try library.load())
        XCTAssertThrowsError(try library.importIPA(fixture()))
        XCTAssertEqual(try Data(contentsOf: index), corrupt)
        XCTAssertTrue(FileManager.default.fileExists(atPath: d.appendingPathComponent(item.id.uuidString + ".ipa").path))
    }
    func testMissingPackageIsNotPresentedAsManaged() throws {
        let d = try directory(); defer { try? FileManager.default.removeItem(at: d) }
        let library = try Library(directory: d); let item = try library.importIPA(fixture())
        try FileManager.default.removeItem(at: d.appendingPathComponent(item.id.uuidString + ".ipa"))
        XCTAssertThrowsError(try library.load())
    }
    func testActualByteCopyBoundCleansStagingAndPreservesSource() throws {
        let d = try directory(); defer { try? FileManager.default.removeItem(at: d) }
        let source = d.appendingPathComponent("source"), dest = d.appendingPathComponent("staging")
        let bytes = Data(repeating: 65, count: 128); try bytes.write(to: source)
        XCTAssertThrowsError(try BoundedFile.copy(source, to: dest, maximumBytes: 64))
        XCTAssertFalse(FileManager.default.fileExists(atPath: dest.path))
        XCTAssertEqual(try Data(contentsOf: source), bytes)
        XCTAssertEqual(try BoundedFile.copy(source, to: dest, maximumBytes: 128), 128)
        XCTAssertThrowsError(try BoundedFile.read(source, maximumBytes: 127))
    }
    func testProfileExpiresAtUseAndRejectsInvalidWildcards() throws {
        let now = Date(timeIntervalSince1970: 1000)
        func plist(_ identifier: String) throws -> Data {
            try PropertyListSerialization.data(fromPropertyList: ["TeamIdentifier":["TEAM"], "ExpirationDate":now.addingTimeInterval(10), "Entitlements":["application-identifier":identifier]], format:.xml, options:0)
        }
        let profile = try ProfileSummary(decodedPlist: plist("TEAM.org.*"), now:now)
        XCTAssertTrue(profile.permits(bundleID:"org.test", team:"TEAM", now:now))
        XCTAssertFalse(profile.permits(bundleID:"org.test", team:"TEAM", now:now.addingTimeInterval(10)))
        XCTAssertFalse(profile.permits(bundleID:"org..test", team:"TEAM", now:now))
        XCTAssertFalse(profile.permits(bundleID:"org.test", team:"OTHER", now:now))
        for bad in ["TEAM.org.*.foo", "TEAM.org**", "TEAM..org", "TEAM.org.☃"] {
            XCTAssertThrowsError(try ProfileSummary(decodedPlist: plist(bad), now:now))
        }
    }
}
