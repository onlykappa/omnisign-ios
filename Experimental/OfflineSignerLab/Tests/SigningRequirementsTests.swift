// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import XCTest
import CodeSignKit

final class SigningRequirementsTests: XCTestCase {
    func word(_ data: Data, _ offset: Int) -> UInt32 { data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) } }
    func testDesignatedRequirementTypeAndTeamEqualityAreEncodedCorrectly() throws {
        let blob = RequirementsCompiler.compileDesignatedRequirement(bundleIdentifier:"org.omnisign.lab",teamIdentifier:"OMNILAB123")
        XCTAssertEqual(word(blob,12),3,"Host requirement type 1 must never stand in for designated type 3")
        let label = Data("subject.OU".utf8)
        let range = try XCTUnwrap(blob.range(of:label))
        let operation = (range.upperBound + 3) & ~3
        XCTAssertEqual(word(blob,operation),1,"matchExists(0) is weaker than the required matchEqual(1)")
    }
    func testUnreadableAndSymbolicResourcesFailInsteadOfBeingSignedAsEmpty() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
        let resource = root.appendingPathComponent("resource.bin")
        try Data("disposable resource".utf8).write(to:resource)
        defer { try? FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:resource.path); try? FileManager.default.removeItem(at:root) }
        try FileManager.default.setAttributes([.posixPermissions:0],ofItemAtPath:resource.path)
        XCTAssertThrowsError(try CodeResourcesBuilder(bundleURL:root,executableName:nil).build())
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:resource.path)
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at:link,withDestinationURL:resource)
        XCTAssertThrowsError(try CodeResourcesBuilder(bundleURL:root,executableName:nil).build())
    }
}
