import XCTest
@testable import OmniCore

final class NativeBinaryInspectorTests: XCTestCase {
    func word(_ value: UInt32, little: Bool = true) -> Data {
        let bytes = (0..<4).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
        return Data(little ? bytes : bytes.reversed())
    }
    func thin(cpu: UInt32 = 0x0100000C, subtype: UInt32 = 0, commands: [Data] = [], fileType: UInt32 = 2) -> Data {
        var data = word(0xFEEDFACF) + word(cpu) + word(subtype) + word(fileType) + word(UInt32(commands.count)) + word(UInt32(commands.reduce(0) { $0 + $1.count })) + word(0) + word(0)
        commands.forEach { data.append($0) }; if data.count < 128 { data.append(Data(count:128 - data.count)) }; return data
    }
    func inspect(_ data: Data) throws -> NativeBinaryInfo {
        try NativeBinaryInspector.inspect(size:data.count) { range in
            guard range.lowerBound >= 0, range.upperBound <= data.count else { throw OmniError.limitsExceeded }
            return data.subdata(in:range)
        }
    }
    func testArchiveInventoriesAdditionalNativePlugins() throws {
        let fixture = Bundle.module.url(forResource: "nativeplugins", withExtension: "ipa", subdirectory: "Fixtures")!
        let result = try IPAInspector().inspect(fixture)
        XCTAssertEqual(result.nativeLibraries.count, 3)
        XCTAssertEqual(result.nativeImages.count, 6)
        XCTAssertTrue(result.nativeLibraries.contains { $0.hasSuffix(".so") })
        XCTAssertTrue(result.nativeLibraries.contains { $0.hasSuffix("NativeHelper") })
    }
    func testArchitectureIsInventoryNotCompatibility() throws {
        let binary = try inspect(thin(subtype:2))
        XCTAssertEqual(binary.slices.first?.architecture,"arm64e")
        XCTAssertFalse(binary.encrypted); XCTAssertFalse(binary.signatureEnvelopePresent)
        XCTAssertNil(binary.slices.first?.xmlEntitlements)
        XCTAssertThrowsError(try inspect(thin(fileType:1)))
    }
    func testEncryptionFlagAndBounds() throws {
        let command = word(0x2C) + word(24) + word(96) + word(16) + word(1) + word(0)
        XCTAssertTrue(try inspect(thin(commands:[command])).encrypted)
        let bad = word(0x2C) + word(24) + word(128) + word(100) + word(1) + word(0)
        XCTAssertThrowsError(try inspect(thin(commands:[bad])))
    }
    func fat(overlap: Bool = false) -> Data {
        var data = word(0xCAFEBABE,little:false) + word(2,little:false)
        for (cpu, offset) in [(UInt32(0x0100000C),UInt32(4096)),(UInt32(0x01000007),UInt32(overlap ? 4096 : 8192))] {
            data.append(word(cpu,little:false)); data.append(word(0,little:false)); data.append(word(offset,little:false)); data.append(word(128,little:false)); data.append(word(12,little:false))
        }
        data.append(Data(count:4096 - data.count)); data.append(thin())
        data.append(Data(count:8192 - data.count)); data.append(thin(cpu:0x01000007))
        return data
    }
    func testFatSlicesAndOverlapRejection() throws {
        let binary = try inspect(fat())
        XCTAssertEqual(binary.slices.map(\.architecture),["arm64","x86_64"])
        XCTAssertEqual(binary.slices.map(\.offset),[4096,8192])
        XCTAssertThrowsError(try inspect(fat(overlap:true)))
    }
    func testMalformedLoadCommandsNeverReadOutsideImage() {
        for command in [word(1) + word(0), word(1) + word(7), word(1) + word(UInt32.max)] {
            XCTAssertThrowsError(try inspect(thin(commands:[command])))
        }
        var large = thin(); large.replaceSubrange(20..<24,with:word(UInt32.max))
        XCTAssertThrowsError(try inspect(large))
        XCTAssertThrowsError(try inspect(Data(repeating:0,count:128)))
        XCTAssertThrowsError(try inspect(thin().prefix(31)))
    }
    func signedEnvelope(entitlements: [String: Any]) throws -> Data {
        let xml = try PropertyListSerialization.data(fromPropertyList:entitlements,format:.xml,options:0)
        let cd = word(0xFADE0C02,little:false) + word(44,little:false) + Data(count:36)
        let ent = word(0xFADE7171,little:false) + word(UInt32(xml.count + 8),little:false) + xml
        let total = 28 + cd.count + ent.count
        let blob = word(0xFADE0CC0,little:false) + word(UInt32(total),little:false) + word(2,little:false) + word(0,little:false) + word(28,little:false) + word(5,little:false) + word(UInt32(28 + cd.count),little:false) + cd + ent
        let command = word(0x1D) + word(16) + word(256) + word(UInt32(blob.count))
        var data = thin(commands:[command]); data.append(Data(count:256 - data.count)); data.append(blob); return data
    }
    func testTypedXMLParsingDoesNotAssertCryptographicValidity() throws {
        // Deliberately fake CodeDirectory, no CMS. Only envelope framing and untrusted values are inspected.
        let binary = try inspect(signedEnvelope(entitlements:["application-identifier":"TEAM.org.lab", "get-task-allow":true,"count":3,"groups":["TEAM.group"],"nested":["enabled":false]]))
        XCTAssertTrue(binary.signatureEnvelopePresent)
        let values = try XCTUnwrap(binary.slices.first?.xmlEntitlements)
        XCTAssertEqual(values["get-task-allow"],.bool(true))
        XCTAssertEqual(values["count"],.integer(3))
        XCTAssertEqual(values["groups"],.array([.string("TEAM.group")]))
        XCTAssertEqual(values["nested"],.dictionary(["enabled":.bool(false)]))
        XCTAssertThrowsError(try inspect(signedEnvelope(entitlements:["float":1.5])))
    }
    func testSignatureRangesAndBlobOverlapsFailClosed() throws {
        let command = word(0x1D) + word(16) + word(32) + word(100)
        XCTAssertThrowsError(try inspect(thin(commands:[command])))
        var image = try signedEnvelope(entitlements:["enabled":true])
        image.replaceSubrange((256 + 24)..<(256 + 28),with:word(28,little:false))
        XCTAssertThrowsError(try inspect(image))
    }
    func testEntitlementDepthIsBounded() {
        var object: Any = "value"
        for _ in 0..<12 { object = ["nested":object] }
        XCTAssertThrowsError(try inspect(signedEnvelope(entitlements:["root":object])))
    }
}
