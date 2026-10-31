import Foundation
import Security
import CryptoKit
import OmniCore

enum AppleTrustState: String { case blocked, offlineCandidate }
enum AppleTrustBlocker: String {
    case timeInvalid, untrustedOrIncompleteChain, nonAppleRoot, missingDevelopmentMarker, ambiguousTeam
}
struct AppleTrustAssessment {
    let state: AppleTrustState
    let blocker: AppleTrustBlocker?
    var canAuthorizeSigning: Bool { false } // Revocation, profile, account and device eligibility are not established here.
}
enum AppleDevelopmentTrust {
    // Official Apple public-root DER SHA-256 pins. Sources and dates: docs/v2/APPLE_TRUST_PINS.md.
    private static let rootHashes: Set<String> = [
        "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
        "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
        "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"
    ]
    static func isKnownAppleRoot(_ data: Data) -> Bool {
        let digest = SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined()
        return rootHashes.contains(digest)
    }
    static func inspect(_ certificate: SecCertificate, intermediates: [SecCertificate] = [], at now: Date = Date()) throws -> AppleTrustAssessment {
        let metadata = try CertificateMetadata(der:SecCertificateCopyData(certificate) as Data)
        guard metadata.validity(at:now) == .valid else { return AppleTrustAssessment(state:.blocked,blocker:.timeInvalid) }
        guard intermediates.count <= 8 else { throw OmniError.limitsExceeded }
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(([certificate] + intermediates) as CFArray,SecPolicyCreateBasicX509(),&trust)
        guard status == errSecSuccess else { throw SecureStoreError(code:status) }
        guard let trust else { throw OmniError.unavailable }
        let networkStatus = SecTrustSetNetworkFetchAllowed(trust,false)
        guard networkStatus == errSecSuccess else { throw SecureStoreError(code:networkStatus) }
        let dateStatus = SecTrustSetVerifyDate(trust,now as CFDate)
        guard dateStatus == errSecSuccess else { throw SecureStoreError(code:dateStatus) }
        guard SecTrustEvaluateWithError(trust,nil), let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let root = chain.last else {
            return AppleTrustAssessment(state:.blocked,blocker:.untrustedOrIncompleteChain)
        }
        guard isKnownAppleRoot(SecCertificateCopyData(root) as Data) else { return AppleTrustAssessment(state:.blocked,blocker:.nonAppleRoot) }
        guard metadata.hasDevelopmentMarker else { return AppleTrustAssessment(state:.blocked,blocker:.missingDevelopmentMarker) }
        let teams = metadata.subjectOrganizationalUnits.filter { value in
            value.utf8.count == 10 && value.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) }
        }
        guard teams.count == 1 else { return AppleTrustAssessment(state:.blocked,blocker:.ambiguousTeam) }
        return AppleTrustAssessment(state:.offlineCandidate,blocker:nil)
    }
}
