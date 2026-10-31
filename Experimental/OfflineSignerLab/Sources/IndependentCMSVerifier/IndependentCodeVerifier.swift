// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import Crypto

public enum CodeVerificationError: Error { case malformed, unsupported, limitExceeded, hashMismatch, unboundSpecialSlot }
public struct CodeMathResult: Sendable {
    public let codePageCount: Int
    public let specialSlotCount: Int
    public var codeAndCMSMathematicallyVerified: Bool { true }
    public var resourceFilesVerified: Bool { false }
    public var appleTrustVerified: Bool { false }
    public var canAuthorizeInstallation: Bool { false }
}

/// Independent strict subset: thin arm64 LE64, SHA256 CodeDirectory v0x20400, detached RSA CMS.
/// No CodeSignKit dependency. External slots bind the exact Info.plist/CodeResources bytes only;
/// resource-file contents, entitlement semantics, loadability, profile eligibility and trust are NOT verified.
public enum IndependentCodeVerifier {
    public static func verify(binary: Data, externalSpecialSlots: [Int: Data] = [:]) throws -> CodeMathResult {
        guard binary.count <= 16_777_216, externalSpecialSlots.count <= 2,
              externalSpecialSlots.keys.allSatisfy({ [1, 3].contains($0) }),
              externalSpecialSlots.values.allSatisfy({ $0.count <= 2_097_152 }) else { throw CodeVerificationError.limitExceeded }
        let data = Data(binary)
        func word(_ offset: Int, little: Bool = false) throws -> Int {
            guard offset >= 0, offset <= data.count - 4 else { throw CodeVerificationError.malformed }
            let bytes = data[offset..<(offset + 4)]
            return (little ? Array(bytes.reversed()) : Array(bytes)).reduce(0) { ($0 << 8) | Int($1) }
        }
        guard data.count >= 48, try word(0) == 0xCFFAEDFE,
              try word(4, little: true) == 0x0100000C,
              [2, 6, 8].contains(try word(12, little: true)) else { throw CodeVerificationError.unsupported }
        let commandCount = try word(16, little: true), commandBytes = try word(20, little: true)
        guard (1...256).contains(commandCount), commandBytes <= 1_048_576, commandBytes <= data.count - 32 else { throw CodeVerificationError.malformed }
        var position = 32, signatureRange: Range<Int>?
        for _ in 0..<commandCount {
            let command = try word(position, little: true), length = try word(position + 4, little: true)
            guard length >= 8, length % 8 == 0, length <= 32 + commandBytes - position else { throw CodeVerificationError.malformed }
            if command == 0x1D {
                guard length == 16, signatureRange == nil else { throw CodeVerificationError.malformed }
                let start = try word(position + 8, little: true), size = try word(position + 12, little: true)
                guard start >= 32 + commandBytes, size >= 12, size <= 2_097_152, start <= data.count - size else { throw CodeVerificationError.malformed }
                signatureRange = start..<(start + size)
            }
            if command == 0x2C {
                guard length >= 24, try word(position + 16, little: true) == 0 else { throw CodeVerificationError.unsupported }
            }
            position += length
        }
        guard position == 32 + commandBytes, let signatureRange, signatureRange.upperBound == data.count else { throw CodeVerificationError.malformed }
        let start = signatureRange.lowerBound, total = try word(start + 4), count = try word(start + 8)
        guard try word(start) == 0xFADE0CC0, (2...5).contains(count), total >= 12 + count * 8,
              total <= signatureRange.count, signatureRange.count - total <= 15,
              data[(start + total)..<signatureRange.upperBound].allSatisfy({ $0 == 0 }) else { throw CodeVerificationError.malformed }
        var blobs: [Int: Data] = [:], ranges: [Range<Int>] = []
        let knownMagic = [0: 0xFADE0C02, 2: 0xFADE0C01, 5: 0xFADE7171, 7: 0xFADE7172, 0x10000: 0xFADE0B01]
        for index in 0..<count {
            let slot = try word(start + 12 + index * 8), offset = try word(start + 16 + index * 8)
            guard let magic = knownMagic[slot], blobs[slot] == nil, offset >= 12 + count * 8, offset <= total - 8 else { throw CodeVerificationError.unsupported }
            let size = try word(start + offset + 4)
            guard try word(start + offset) == magic, size >= 8, size <= total - offset else { throw CodeVerificationError.malformed }
            ranges.append(offset..<(offset + size))
            blobs[slot] = data.subdata(in: (start + offset)..<(start + offset + size))
        }
        var cursor = 12 + count * 8
        for range in ranges.sorted(by: { $0.lowerBound < $1.lowerBound }) {
            guard range.lowerBound == cursor else { throw CodeVerificationError.malformed }
            cursor = range.upperBound
        }
        guard cursor == total, let cd = blobs[0], let cms = blobs[0x10000], blobs[2] != nil else { throw CodeVerificationError.malformed }
        func cdWord(_ offset: Int) throws -> Int {
            guard offset >= 0, offset <= cd.count - 4 else { throw CodeVerificationError.malformed }
            return cd[offset..<(offset + 4)].reduce(0) { ($0 << 8) | Int($1) }
        }
        guard cd.count >= 88, try cdWord(8) == 0x20400, cd[36] == 32, cd[37] == 2,
              [12, 14].contains(cd[39]), try cdWord(44) == 0,
              try cdWord(56) == 0, try cdWord(60) == 0 else { throw CodeVerificationError.unsupported }
        let hashes = try cdWord(16), special = try cdWord(24), pages = try cdWord(28), limit = try cdWord(32)
        let pageSize = 1 << Int(cd[39])
        guard limit == start, special <= 7, pages == (limit + pageSize - 1) / pageSize,
              hashes >= 88 + special * 32, hashes <= cd.count,
              pages * 32 == cd.count - hashes else { throw CodeVerificationError.malformed }
        let stringEnd = hashes - special * 32
        let identifierOffset = try cdWord(20)
        guard identifierOffset >= 88, identifierOffset < stringEnd else { throw CodeVerificationError.malformed }
        for offset in [identifierOffset, try cdWord(48)] {
            guard offset == 0 || (offset >= 88 && offset < stringEnd && cd[offset..<stringEnd].contains(0)) else { throw CodeVerificationError.malformed }
        }
        for page in 0..<pages {
            let bytes = data.subdata(in: (page * pageSize)..<min((page + 1) * pageSize, limit))
            let expected = cd.subdata(in: (hashes + page * 32)..<(hashes + (page + 1) * 32))
            guard Data(SHA256.hash(data: bytes)) == expected else { throw CodeVerificationError.hashMismatch }
        }
        var binding = externalSpecialSlots
        for slot in [2, 5, 7] { if let blob = blobs[slot] { binding[slot] = blob } }
        guard binding.keys.allSatisfy({ $0 <= special }) else { throw CodeVerificationError.unboundSpecialSlot }
        if special > 0 {
            for slot in 1...special {
                let expected = cd.subdata(in: (hashes - slot * 32)..<(hashes - (slot - 1) * 32))
                if let blob = binding[slot] {
                    guard Data(SHA256.hash(data: blob)) == expected else { throw CodeVerificationError.hashMismatch }
                } else {
                    guard expected.allSatisfy({ $0 == 0 }) else { throw CodeVerificationError.unboundSpecialSlot }
                }
            }
        }
        let result = try IndependentCMSVerifier.verify(signature: Data(cms.dropFirst(8)), detachedContent: cd)
        guard result.signatureMathematicallyVerified else { throw CodeVerificationError.hashMismatch }
        return CodeMathResult(codePageCount: pages, specialSlotCount: special)
    }
}
