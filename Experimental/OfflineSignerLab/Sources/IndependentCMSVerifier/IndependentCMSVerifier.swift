// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import Crypto
import CryptoExtras

public enum CMSVerificationError: Error { case malformed, unsupported, contentMismatch, invalidSignature, limitExceeded }
public struct CMSMathResult: Sendable {
    public let signatureMathematicallyVerified: Bool
    public var appleTrustVerified: Bool { false }
    public var certificateTimeChecked: Bool { false }
    public var canAuthorizeInstallation: Bool { false }
}
/// Independent bounded DER/CMS path. Does not import CodeSignKit or establish a certificate trust chain.
public enum IndependentCMSVerifier {
    public static func verify(signature: Data, detachedContent: Data) throws -> CMSMathResult {
        guard signature.count <= 2_097_152, detachedContent.count <= 16_777_216 else { throw CMSVerificationError.limitExceeded }
        let bytes = Array(signature), outer = try Node.read(Array(signature), start:0, limit:signature.count)
        guard outer.tag == 0x30, outer.end == bytes.count else { throw CMSVerificationError.malformed }
        let info = try outer.children(bytes)
        guard info.count == 2, info[0].oid(bytes) == signedDataOID, info[1].tag == 0xA0 else { throw CMSVerificationError.unsupported }
        let context = try info[1].children(bytes)
        guard context.count == 1, context[0].tag == 0x30 else { throw CMSVerificationError.malformed }
        let signed = try context[0].children(bytes)
        guard signed.count == 5, signed[0].tag == 0x02, signed[1].tag == 0x31, signed[2].tag == 0x30,
              signed[3].tag == 0xA0, signed[4].tag == 0x31 else { throw CMSVerificationError.unsupported }
        let digestAlgorithms = try signed[1].children(bytes)
        guard digestAlgorithms.count == 1, try algorithm(digestAlgorithms[0], bytes) == sha256OID else { throw CMSVerificationError.unsupported }
        let content = try signed[2].children(bytes)
        guard content.count == 1, content[0].oid(bytes) == dataOID else { throw CMSVerificationError.unsupported }
        let signers = try signed[4].children(bytes), certificates = try signed[3].children(bytes)
        guard signers.count == 1, certificates.count <= 8, signers[0].tag == 0x30 else { throw CMSVerificationError.unsupported }
        let signer = try signers[0].children(bytes)
        guard signer.count == 6, signer[0].tag == 0x02, signer[1].tag == 0x30, signer[3].tag == 0xA0,
              signer[5].tag == 0x04, try algorithm(signer[2],bytes) == sha256OID else { throw CMSVerificationError.unsupported }
        let signatureAlgorithm = try algorithm(signer[4],bytes)
        guard signatureAlgorithm == rsaOID || signatureAlgorithm == sha256RSAOID else { throw CMSVerificationError.unsupported }
        let sid = try signer[1].children(bytes)
        guard sid.count == 2, sid[0].tag == 0x30, sid[1].tag == 0x02 else { throw CMSVerificationError.unsupported }
        var key: _RSA.Signing.PublicKey?
        for certificate in certificates {
            guard certificate.tag == 0x30 else { throw CMSVerificationError.malformed }
            let sequence = try certificate.children(bytes)
            guard sequence.count == 3, sequence[0].tag == 0x30 else { throw CMSVerificationError.malformed }
            let tbs = try sequence[0].children(bytes), base = (try sequence[0].children(bytes)).first?.tag == 0xA0 ? 1 : 0
            guard tbs.count >= base + 6 else { throw CMSVerificationError.malformed }
            if tbs[base].encoded(bytes) == sid[1].encoded(bytes), tbs[base + 2].encoded(bytes) == sid[0].encoded(bytes) {
                guard key == nil else { throw CMSVerificationError.malformed }
                key = try _RSA.Signing.PublicKey(derRepresentation:tbs[base + 5].encoded(bytes))
            }
        }
        guard let key, key.keySizeInBits >= 2048 else { throw CMSVerificationError.unsupported }
        let attributes = try signer[3].children(bytes)
        guard attributes.count <= 32 else { throw CMSVerificationError.limitExceeded }
        var identifiers = Set<Data>(), previous: Data?, digest: Data?, type: Data?
        for attribute in attributes {
            guard attribute.tag == 0x30 else { throw CMSVerificationError.malformed }
            let encoded = attribute.encoded(bytes)
            if let previous, encoded.lexicographicallyPrecedes(previous) { throw CMSVerificationError.malformed }
            previous = encoded
            let pair = try attribute.children(bytes)
            guard pair.count == 2, pair[0].tag == 0x06, pair[1].tag == 0x31 else { throw CMSVerificationError.malformed }
            let oid = Data(bytes[pair[0].body..<pair[0].end])
            guard identifiers.insert(oid).inserted else { throw CMSVerificationError.malformed }
            let values = try pair[1].children(bytes)
            guard values.count == 1 else { throw CMSVerificationError.unsupported }
            if Array(oid) == contentTypeOID { guard values[0].tag == 0x06 else { throw CMSVerificationError.malformed }; type = Data(bytes[values[0].body..<values[0].end]) }
            if Array(oid) == messageDigestOID { guard values[0].tag == 0x04 else { throw CMSVerificationError.malformed }; digest = Data(bytes[values[0].body..<values[0].end]) }
        }
        guard type == Data(dataOID), digest == Data(SHA256.hash(data:detachedContent)) else { throw CMSVerificationError.contentMismatch }
        var signedAttributes = signer[3].encoded(bytes)
        signedAttributes[0] = 0x31 // DER SET OF encoding, not the implicit context tag, is signed by CMS.
        let rawSignature = Data(bytes[signer[5].body..<signer[5].end])
        let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation:rawSignature)
        guard key.isValidSignature(rsaSignature, for:SHA256.hash(data:signedAttributes), padding:.insecurePKCS1v1_5) else { throw CMSVerificationError.invalidSignature }
        return CMSMathResult(signatureMathematicallyVerified:true)
    }
    private static func algorithm(_ node: Node, _ bytes: [UInt8]) throws -> [UInt8] {
        guard node.tag == 0x30 else { throw CMSVerificationError.malformed }
        let elements = try node.children(bytes)
        guard (1...2).contains(elements.count), elements[0].tag == 0x06,
              elements.count == 1 || (elements[1].tag == 0x05 && elements[1].body == elements[1].end) else { throw CMSVerificationError.unsupported }
        return elements[0].oid(bytes)
    }
    private static let signedDataOID: [UInt8] = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02]
    private static let dataOID: [UInt8] = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01]
    private static let sha256OID: [UInt8] = [0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01]
    private static let rsaOID: [UInt8] = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01]
    private static let sha256RSAOID: [UInt8] = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B]
    private static let contentTypeOID: [UInt8] = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x03]
    private static let messageDigestOID: [UInt8] = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04]
}
private struct Node {
    let tag: UInt8, start: Int, body: Int, end: Int
    func encoded(_ bytes: [UInt8]) -> Data { Data(bytes[start..<end]) }
    func oid(_ bytes: [UInt8]) -> [UInt8] { tag == 0x06 ? Array(bytes[body..<end]) : [] }
    static func read(_ bytes: [UInt8], start: Int, limit: Int) throws -> Self {
        guard start >= 0, start + 2 <= limit, limit <= bytes.count else { throw CMSVerificationError.malformed }
        let tag = bytes[start], first = bytes[start + 1]
        guard tag & 0x1F != 0x1F else { throw CMSVerificationError.unsupported }
        var body = start + 2, length = Int(first)
        if first & 0x80 != 0 {
            let count = Int(first & 0x7F)
            guard count > 0, count <= 3, body + count <= limit, bytes[body] != 0 else { throw CMSVerificationError.malformed }
            length = 0
            for byte in bytes[body..<(body + count)] { length = length * 256 + Int(byte) }
            guard length >= 128 else { throw CMSVerificationError.malformed }
            body += count
        }
        guard length <= limit - body else { throw CMSVerificationError.malformed }
        return Self(tag:tag,start:start,body:body,end:body + length)
    }
    func children(_ bytes: [UInt8]) throws -> [Node] {
        var result: [Node] = [], position = body
        while position < end {
            guard result.count < 256 else { throw CMSVerificationError.limitExceeded }
            let node = try Self.read(bytes,start:position,limit:end)
            result.append(node); position = node.end
        }
        return result
    }
}
