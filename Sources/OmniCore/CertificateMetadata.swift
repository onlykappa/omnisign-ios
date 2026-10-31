import Foundation

public enum CertificateValidity: String, Codable, Sendable { case notYetValid, valid, expired }
/// Bounded DER metadata inspection. Neither ASN.1 parsing nor an Apple-related OID proves trust or private-key ownership.
public struct CertificateMetadata: Equatable, Sendable {
    public let notBefore: Date
    public let notAfter: Date
    public let subjectOrganizationalUnits: [String]
    public let hasDevelopmentMarker: Bool
    public func validity(at now: Date = Date()) -> CertificateValidity {
        if now < notBefore { return .notYetValid }
        return now >= notAfter ? .expired : .valid
    }
    public init(der: Data) throws {
        guard der.count <= 2_097_152 else { throw OmniError.limitsExceeded }
        let bytes = Array(der)
        let outer = try DERNode.read(bytes, at: 0, limit: bytes.count)
        guard outer.tag == 0x30, outer.end == bytes.count else { throw OmniError.invalidCertificate }
        let certificate = try outer.children(bytes)
        guard certificate.count == 3, certificate[0].tag == 0x30, certificate[1].tag == 0x30, certificate[2].tag == 0x03 else { throw OmniError.invalidCertificate }
        let tbs = try certificate[0].children(bytes)
        let base = tbs.first?.tag == 0xA0 ? 1 : 0
        guard tbs.count >= base + 6, tbs[base].tag == 0x02,
              tbs[base + 1].tag == 0x30, tbs[base + 2].tag == 0x30,
              tbs[base + 3].tag == 0x30, tbs[base + 4].tag == 0x30, tbs[base + 5].tag == 0x30 else { throw OmniError.invalidCertificate }
        let validity = try tbs[base + 3].children(bytes)
        guard validity.count == 2 else { throw OmniError.invalidCertificate }
        notBefore = try Self.date(validity[0], bytes); notAfter = try Self.date(validity[1], bytes)
        guard notAfter > notBefore else { throw OmniError.invalidCertificate }
        var units: [String] = []
        for set in try tbs[base + 4].children(bytes) {
            guard set.tag == 0x31 else { throw OmniError.invalidCertificate }
            for sequence in try set.children(bytes) {
                guard sequence.tag == 0x30 else { throw OmniError.invalidCertificate }
                let pair = try sequence.children(bytes)
                guard pair.count == 2, pair[0].tag == 0x06 else { throw OmniError.invalidCertificate }
                if Array(bytes[pair[0].body..<pair[0].end]) == [0x55, 0x04, 0x0B] {
                    guard [0x0C, 0x13, 0x16].contains(pair[1].tag), pair[1].end - pair[1].body <= 256,
                          let value = String(bytes: bytes[pair[1].body..<pair[1].end], encoding: .utf8),
                          !value.unicodeScalars.contains(where: { $0.value < 32 }) else { throw OmniError.invalidCertificate }
                    units.append(value)
                }
            }
        }
        subjectOrganizationalUnits = units
        let developmentOIDs: [[UInt8]] = [[0x2A,0x86,0x48,0x86,0xF7,0x63,0x64,0x06,0x01,0x02], [0x2A,0x86,0x48,0x86,0xF7,0x63,0x64,0x06,0x01,0x0C]]
        var marker = false
        for extensionNode in tbs.dropFirst(base + 6) where extensionNode.tag == 0xA3 {
            let wrapped = try extensionNode.children(bytes)
            guard wrapped.count == 1, wrapped[0].tag == 0x30 else { throw OmniError.invalidCertificate }
            for entry in try wrapped[0].children(bytes) {
                guard entry.tag == 0x30 else { throw OmniError.invalidCertificate }
                let fields = try entry.children(bytes)
                guard (2...3).contains(fields.count), fields[0].tag == 0x06, fields.last?.tag == 0x04 else { throw OmniError.invalidCertificate }
                if developmentOIDs.contains(Array(bytes[fields[0].body..<fields[0].end])) { marker = true }
            }
        }
        hasDevelopmentMarker = marker
    }
    private static func date(_ node: DERNode, _ bytes: [UInt8]) throws -> Date {
        guard let value = String(bytes: bytes[node.body..<node.end], encoding: .ascii), value.hasSuffix("Z") else { throw OmniError.invalidCertificate }
        let yearDigits: Int
        if node.tag == 0x17, value.count == 13 { yearDigits = 2 }
        else if node.tag == 0x18, value.count == 15 { yearDigits = 4 }
        else { throw OmniError.invalidCertificate }
        let digits = Array(value.dropLast())
        guard digits.allSatisfy({ $0.isASCII && $0.isNumber }), let rawYear = Int(String(digits.prefix(yearDigits))) else { throw OmniError.invalidCertificate }
        let year = yearDigits == 2 ? rawYear + (rawYear >= 50 ? 1900 : 2000) : rawYear
        func number(_ offset: Int) -> Int { Int(String(digits[offset..<(offset + 2)]))! }
        var calendar = Calendar(identifier: .gregorian); calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let components = DateComponents(year: year, month: number(yearDigits), day: number(yearDigits + 2), hour: number(yearDigits + 4), minute: number(yearDigits + 6), second: number(yearDigits + 8))
        guard let result = calendar.date(from: components) else { throw OmniError.invalidCertificate }
        let roundtrip = calendar.dateComponents([.year,.month,.day,.hour,.minute,.second], from: result)
        guard roundtrip.year == components.year, roundtrip.month == components.month, roundtrip.day == components.day,
              roundtrip.hour == components.hour, roundtrip.minute == components.minute, roundtrip.second == components.second else { throw OmniError.invalidCertificate }
        return result
    }
}
struct DERNode {
    let tag: UInt8
    let body: Int
    let end: Int
    static func read(_ bytes: [UInt8], at offset: Int, limit: Int) throws -> Self {
        guard offset >= 0, offset + 2 <= limit, limit <= bytes.count else { throw OmniError.invalidCertificate }
        let tag = bytes[offset], first = bytes[offset + 1]
        guard tag & 0x1F != 0x1F else { throw OmniError.invalidCertificate }
        var start = offset + 2, length = Int(first)
        if first & 0x80 != 0 {
            let count = Int(first & 0x7F)
            guard count > 0, count <= 3, start + count <= limit, bytes[start] != 0 else { throw OmniError.invalidCertificate }
            length = 0
            for byte in bytes[start..<(start + count)] { length = length * 256 + Int(byte) }
            guard length >= 128 else { throw OmniError.invalidCertificate }
            start += count
        }
        guard length <= limit - start else { throw OmniError.invalidCertificate }
        return Self(tag: tag, body: start, end: start + length)
    }
    func children(_ bytes: [UInt8]) throws -> [Self] {
        var nodes: [Self] = [], position = body
        while position < end {
            guard nodes.count < 128 else { throw OmniError.invalidCertificate }
            let node = try Self.read(bytes, at: position, limit: end)
            nodes.append(node); position = node.end
        }
        return nodes
    }
}
