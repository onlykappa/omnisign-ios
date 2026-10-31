import Foundation
import CoreFoundation

public indirect enum EntitlementValue: Codable, Equatable, Sendable {
    case string(String), bool(Bool), integer(Int64), data(Data), array([EntitlementValue]), dictionary([String: EntitlementValue])
    static func parse(_ value: Any, depth: Int = 0, remaining: inout Int) throws -> Self {
        remaining -= 1
        guard depth <= 8, remaining >= 0 else { throw OmniError.limitsExceeded }
        if let string = value as? String {
            guard string.utf8.count <= 65_536 else { throw OmniError.limitsExceeded }; return .string(string)
        }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return .bool(number.boolValue) }
            let type = String(cString: number.objCType)
            guard !["f", "d"].contains(type), type != "Q" || number.uint64Value <= UInt64(Int64.max) else { throw OmniError.malformedBundle }
            return .integer(number.int64Value)
        }
        if let bytes = value as? Data { guard bytes.count <= 65_536 else { throw OmniError.limitsExceeded }; return .data(bytes) }
        if let array = value as? [Any] { return .array(try array.map { try parse($0, depth: depth + 1, remaining: &remaining) }) }
        if let dict = value as? [String: Any] {
            var result: [String: EntitlementValue] = [:]
            for (key, item) in dict {
                guard key.utf8.count <= 1024 else { throw OmniError.limitsExceeded }
                result[key] = try parse(item, depth: depth + 1, remaining: &remaining)
            }
            return .dictionary(result)
        }
        throw OmniError.malformedBundle
    }
}
public struct NativeSlice: Codable, Equatable, Sendable {
    public let cpuType: UInt32
    public let cpuSubtype: UInt32
    public let fileType: UInt32
    public let offset: Int
    public let size: Int
    public let encrypted: Bool
    public let signatureEnvelopePresent: Bool
    public let xmlEntitlements: [String: EntitlementValue]?
    public let derEntitlementsPresent: Bool
    public var architecture: String {
        switch cpuType {
        case 0x0100000C: return cpuSubtype & 0x00FFFFFF == 2 ? "arm64e" : "arm64"
        case 12: return "arm"
        case 0x01000007: return "x86_64"
        case 7: return "i386"
        default: return "unknown(\(cpuType))"
        }
    }
}
public struct NativeBinaryInfo: Codable, Equatable, Sendable {
    public let slices: [NativeSlice]
    public var encrypted: Bool { slices.contains(where: \.encrypted) }
    /// Envelope framing is never a claim of signature validity, Apple trust, or install compatibility.
    public var signatureEnvelopePresent: Bool { !slices.isEmpty && slices.allSatisfy(\.signatureEnvelopePresent) }
}
public struct NativeImageRecord: Codable, Equatable, Sendable {
    public let path: String
    public let info: NativeBinaryInfo
}

public enum NativeBinaryInspector {
    /// Reads bounded metadata ranges; callers must supply exact bytes and independently establish archive integrity.
    public static func inspect(size: Int, read: (Range<Int>) throws -> Data) throws -> NativeBinaryInfo {
        guard size >= 28, size <= 536_870_912 else { throw OmniError.unsupportedExecutable }
        func bytes(_ range: Range<Int>) throws -> [UInt8] {
            guard range.lowerBound >= 0, range.upperBound <= size, range.count <= 16_777_216 else { throw OmniError.limitsExceeded }
            let data = try read(range)
            guard data.count == range.count else { throw OmniError.unsupportedExecutable }
            return Array(data)
        }
        let first = try bytes(0..<8), magic = u32(first, 0, little: false)
        let fat64 = magic == 0xCAFEBABF || magic == 0xBFBAFECA
        if [UInt32(0xCAFEBABE), 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA].contains(magic) {
            let little = magic == 0xBEBAFECA || magic == 0xBFBAFECA
            let count = Int(u32(first, 4, little: little)), stride = fat64 ? 32 : 20
            guard count > 0, count <= 32, 8 + count * stride <= size else { throw OmniError.unsupportedExecutable }
            let table = try bytes(8..<(8 + count * stride))
            var definitions: [(offset: Int, size: Int, cpu: UInt32, subtype: UInt32)] = []
            var architectures = Set<String>()
            for index in 0..<count {
                let base = index * stride, cpu = u32(table, base, little: little), subtype = u32(table, base + 4, little: little)
                let offset = fat64 ? u64(table, base + 8, little: little) : UInt64(u32(table, base + 8, little: little))
                let length = fat64 ? u64(table, base + 16, little: little) : UInt64(u32(table, base + 12, little: little))
                let alignment = u32(table, base + (fat64 ? 24 : 16), little: little)
                guard offset >= UInt64(8 + count * stride), offset <= UInt64(size), length >= 28, length <= UInt64(size) - offset,
                      alignment <= 31, offset % (UInt64(1) << alignment) == 0,
                      architectures.insert("\(cpu):\(subtype)").inserted else { throw OmniError.unsupportedExecutable }
                definitions.append((Int(offset), Int(length), cpu, subtype))
            }
            let sorted = definitions.sorted { $0.offset < $1.offset }
            for index in sorted.indices.dropFirst() {
                guard sorted[index - 1].offset + sorted[index - 1].size <= sorted[index].offset else { throw OmniError.unsupportedExecutable }
            }
            let slices = try definitions.map { definition -> NativeSlice in
                let slice = try thin(offset: definition.offset, size: definition.size, read: bytes)
                guard slice.cpuType == definition.cpu, slice.cpuSubtype == definition.subtype else { throw OmniError.unsupportedExecutable }
                return slice
            }
            return NativeBinaryInfo(slices: slices)
        }
        return NativeBinaryInfo(slices: [try thin(offset: 0, size: size, read: bytes)])
    }
    private static func thin(offset: Int, size: Int, read: (Range<Int>) throws -> [UInt8]) throws -> NativeSlice {
        let initial = try read(offset..<(offset + 28)), magic = u32(initial, 0, little: false)
        let little = magic == 0xCEFAEDFE || magic == 0xCFFAEDFE
        let is64 = magic == 0xFEEDFACF || magic == 0xCFFAEDFE
        guard [UInt32(0xFEEDFACE), 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE].contains(magic) else { throw OmniError.unsupportedExecutable }
        let headerSize = is64 ? 32 : 28, commands = Int(u32(initial, 16, little: little)), commandSize = Int(u32(initial, 20, little: little))
        let cpu = u32(initial, 4, little: little), subtype = u32(initial, 8, little: little), fileType = u32(initial, 12, little: little)
        guard [UInt32(2),6,8].contains(fileType), commands <= 8192, commands * 8 <= commandSize,
              commandSize <= 1_048_576 - headerSize, headerSize + commandSize <= size else { throw OmniError.unsupportedExecutable }
        let data = try read(offset..<(offset + headerSize + commandSize))
        var position = headerSize, encrypted = false, signature: (offset: Int, size: Int)?
        for _ in 0..<commands {
            guard position + 8 <= data.count else { throw OmniError.unsupportedExecutable }
            let cmd = u32(data, position, little: little), length = Int(u32(data, position + 4, little: little))
            guard length >= 8, length % 4 == 0, length <= data.count - position else { throw OmniError.unsupportedExecutable }
            if cmd == 0x21 || cmd == 0x2C {
                guard length >= (cmd == 0x2C ? 24 : 20) else { throw OmniError.unsupportedExecutable }
                let cryptOffset = Int(u32(data, position + 8, little: little)), cryptSize = Int(u32(data, position + 12, little: little))
                guard cryptOffset <= size, cryptSize <= size - cryptOffset else { throw OmniError.unsupportedExecutable }
                encrypted = encrypted || u32(data, position + 16, little: little) != 0
            }
            if cmd == 0x1D {
                guard length == 16, signature == nil else { throw OmniError.unsupportedExecutable }
                let start = Int(u32(data, position + 8, little: little)), length = Int(u32(data, position + 12, little: little))
                guard start >= headerSize + commandSize, start <= size, length >= 12, length <= size - start, length <= 16_777_216 else { throw OmniError.unsupportedExecutable }
                signature = (start, length)
            }
            position += length
        }
        guard position == data.count else { throw OmniError.unsupportedExecutable }
        var entitlements: [String: EntitlementValue]?, der = false
        if let signature {
            let header = try read((offset + signature.offset)..<(offset + signature.offset + 12))
            let total = Int(u32(header, 4)), count = Int(u32(header, 8))
            guard u32(header, 0) == 0xFADE0CC0, total >= 12, total <= signature.size, count <= 64, 12 + count * 8 <= total else { throw OmniError.unsupportedExecutable }
            let blob = try read((offset + signature.offset)..<(offset + signature.offset + total))
            var ranges: [Range<Int>] = [], slots = Set<UInt32>()
            for i in 0..<count {
                let slot = u32(blob, 12 + i * 8), start = Int(u32(blob, 16 + i * 8))
                guard slots.insert(slot).inserted, start >= 12 + count * 8, start + 8 <= blob.count else { throw OmniError.unsupportedExecutable }
                let magic = u32(blob, start), length = Int(u32(blob, start + 4))
                guard length >= 8, length <= blob.count - start else { throw OmniError.unsupportedExecutable }
                let range = start..<(start + length)
                guard ranges.allSatisfy({ !$0.overlaps(range) }) else { throw OmniError.unsupportedExecutable }
                ranges.append(range)
                if slot == 0 { guard magic == 0xFADE0C02, length >= 44 else { throw OmniError.unsupportedExecutable } }
                if slot == 5 {
                    guard magic == 0xFADE7171, length <= 1_048_576 else { throw OmniError.unsupportedExecutable }
                    let object = try PropertyListSerialization.propertyList(from: Data(blob[(start + 8)..<(start + length)]), format: nil)
                    var budget = 4096
                    guard case .dictionary(let dictionary) = try EntitlementValue.parse(object, remaining: &budget) else { throw OmniError.malformedBundle }
                    entitlements = dictionary
                }
                if slot == 7 { guard magic == 0xFADE7172 else { throw OmniError.unsupportedExecutable }; der = true }
            }
            guard slots.contains(0) else { throw OmniError.unsupportedExecutable }
        }
        return NativeSlice(cpuType: cpu, cpuSubtype: subtype, fileType: fileType, offset: offset, size: size, encrypted: encrypted,
                           signatureEnvelopePresent: signature != nil, xmlEntitlements: entitlements, derEntitlementsPresent: der)
    }
    private static func u32(_ data: [UInt8], _ offset: Int, little: Bool = false) -> UInt32 {
        let bytes = data[offset..<(offset + 4)]
        return (little ? Array(bytes.reversed()) : Array(bytes)).reduce(0) { ($0 << 8) | UInt32($1) }
    }
    private static func u64(_ data: [UInt8], _ offset: Int, little: Bool) -> UInt64 {
        let bytes = data[offset..<(offset + 8)]
        return (little ? Array(bytes.reversed()) : Array(bytes)).reduce(0) { ($0 << 8) | UInt64($1) }
    }
}
