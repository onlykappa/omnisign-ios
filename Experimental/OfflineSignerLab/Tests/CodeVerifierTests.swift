// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import XCTest
import CodeSignKit
import IndependentCMSVerifier

final class CodeVerifierTests: XCTestCase {
    func fixture() throws -> (binary: Data, slots: [Int: Data], cms: Data) {
        let (identity, password) = try PKCS12SecurityTests.authenticatedFixture(encrypt: false)
        let signer = CMSSigner(p12Data: identity, password: password)
        var code = Data(repeating: 0, count: 512)
        func write(_ value: UInt32, at offset: Int) { for i in 0..<4 { code[offset + i] = UInt8((value >> (i * 8)) & 255) } }
        write(0xFEEDFACF, at: 0); write(0x0100000C, at: 4); write(2, at: 12)
        write(1, at: 16); write(16, at: 20); write(0x1D, at: 32); write(16, at: 36); write(512, at: 40)
        let slots = [1: Data("synthetic Info.plist binding".utf8), 3: Data("synthetic resource seal binding".utf8)]
        let requirement = RequirementsCompiler.compileDesignatedRequirement(bundleIdentifier: "org.omnisign.lab", teamIdentifier: "OMNILAB123")
        func signature() throws -> (Data, Data) {
            let builder = CodeDirectoryBuilder(binaryData: code, codeLimit: code.count,
                                               bundleIdentifier: "org.omnisign.lab", teamIdentifier: "OMNILAB123")
            for (slot, bytes) in slots { builder.setSpecialSlot(UInt32(slot), data: bytes) }
            builder.setSpecialSlot(2, data: requirement)
            let cd = builder.build(), cms = try signer.sign(codeDirectoryData: cd)
            let superblob = SuperBlobBuilder()
            superblob.addBlob(type: 0, data: cd); superblob.addBlob(type: 2, data: requirement)
            superblob.addBlob(type: 0x10000, data: cms)
            var blob = superblob.build(); blob.append(Data(repeating: 0, count: (16 - blob.count % 16) % 16))
            return (blob, cms)
        }
        let (initial, _) = try signature(); write(UInt32(initial.count), at: 44)
        let (blob, cms) = try signature()
        XCTAssertEqual(initial.count, blob.count)
        code.append(blob)
        // Structurally framed signing fixture only, not a loadable executable/device acceptance app.
        return (code, slots, cms)
    }
    func testIndependentCodeAndCMSBindingsNeverGrantTrustOrResourceCoverage() throws {
        let value = try fixture()
        let result = try IndependentCodeVerifier.verify(binary: value.binary, externalSpecialSlots: value.slots)
        XCTAssertTrue(result.codeAndCMSMathematicallyVerified)
        XCTAssertEqual(result.codePageCount, 1); XCTAssertEqual(result.specialSlotCount, 3)
        XCTAssertFalse(result.appleTrustVerified); XCTAssertFalse(result.canAuthorizeInstallation)
        XCTAssertFalse(result.resourceFilesVerified)
    }
    func testCodeAndCMSTamperingAreBothRejected() throws {
        let value = try fixture()
        var code = value.binary; code[128] ^= 1
        XCTAssertThrowsError(try IndependentCodeVerifier.verify(binary: code, externalSpecialSlots: value.slots))
        let range = try XCTUnwrap(value.binary.range(of: value.cms))
        var cms = value.binary; cms[range.upperBound - 1] ^= 1
        XCTAssertThrowsError(try IndependentCodeVerifier.verify(binary: cms, externalSpecialSlots: value.slots))
    }
    func testUnboundOrModifiedSpecialSlotsCannotSucceed() throws {
        let value = try fixture()
        XCTAssertThrowsError(try IndependentCodeVerifier.verify(binary: value.binary))
        var slots = value.slots; slots[3] = Data("tampered seal".utf8)
        XCTAssertThrowsError(try IndependentCodeVerifier.verify(binary: value.binary, externalSpecialSlots: slots))
    }
    func testTruncationOverlappingBlobsAndUnhashedTailAreRejected() throws {
        let value = try fixture()
        var overlap = value.binary
        // Make the requirements index overlap the CodeDirectory, independently of CMS validity.
        overlap.replaceSubrange(536..<540, with: value.binary[528..<532])
        for data in [Data(), Data(value.binary.prefix(100)), value.binary + Data([0x42]), overlap] {
            XCTAssertThrowsError(try IndependentCodeVerifier.verify(binary: data, externalSpecialSlots: value.slots))
        }
    }
}
