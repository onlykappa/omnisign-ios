// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import Crypto
import CryptoExtras
import CodeSignKit

/// A new non-Apple test key/certificate per call. Never accepts owner identity material.
public struct SyntheticSigningIdentity: Sendable {
    public let certificateDER: Data
    /// Unencrypted, memory-only synthetic PFX; must not be used for owner credentials or persisted by an app.
    public let ephemeralPKCS12: Data
}
public enum SyntheticIdentityFactory {
    public static func generate(at now: Date = Date()) throws -> SyntheticSigningIdentity {
        let key = try _RSA.Signing.PrivateKey(keySize:.bits2048)
        func join(_ pieces: Data...) -> Data { var data = Data(); for piece in pieces { data.append(piece) }; return data }
        func attribute(_ oid: String, _ value: String) -> Data {
            ASN1Helper.set(ASN1Helper.sequence(join(ASN1Helper.encodeOID(oid),ASN1Helper.encodeTLV(tag:0x0C,value:Data(value.utf8)))))
        }
        func ext(_ oid: String, value: Data, critical: Bool = false) -> Data {
            let flag = critical ? ASN1Helper.encodeTLV(tag:0x01,value:Data([0xFF])) : Data()
            return ASN1Helper.sequence(join(ASN1Helper.encodeOID(oid),flag,ASN1Helper.octetString(value)))
        }
        let name = ASN1Helper.sequence(join(attribute("2.5.4.3","OmniSign Disposable Lab"),attribute("2.5.4.11","OMNILAB123")))
        let algorithm = ASN1Helper.algorithmIdentifier(oidData:ASN1Helper.oidSha256WithRSAEncryption,hasNullParam:true)
        var random = SystemRandomNumberGenerator()
        var serial = Data((0..<16).map { _ in UInt8.random(in:0...255,using:&random) }); serial[0] = (serial[0] & 0x7F) | 1
        let validity = ASN1Helper.sequence(join(ASN1Helper.utcTime(now.addingTimeInterval(-60)),ASN1Helper.utcTime(now.addingTimeInterval(86_400))))
        let extensions = ASN1Helper.contextual(3,content:ASN1Helper.sequence(join(
            ext("2.5.29.19",value:ASN1Helper.sequence(Data()),critical:true),
            ext("2.5.29.15",value:ASN1Helper.encodeTLV(tag:0x03,value:Data([7,0x80])),critical:true),
            ext("2.5.29.37",value:ASN1Helper.sequence(ASN1Helper.encodeOID("1.3.6.1.5.5.7.3.3")))
        )),constructed:true)
        let tbs = ASN1Helper.sequence(join(ASN1Helper.contextual(0,content:ASN1Helper.integer(2),constructed:true),ASN1Helper.integer(data:serial),algorithm,name,validity,name,key.publicKey.derRepresentation,extensions))
        let signature = try key.signature(for:SHA256.hash(data:tbs),padding:.insecurePKCS1v1_5)
        let certificate = ASN1Helper.sequence(join(tbs,algorithm,ASN1Helper.bitString(signature.rawRepresentation)))
        let pfx = try PKCS12Builder.build(certificateDER:certificate,privateKeyDER:key.derRepresentation,password:nil)
        return SyntheticSigningIdentity(certificateDER:certificate,ephemeralPKCS12:pfx)
    }
}
