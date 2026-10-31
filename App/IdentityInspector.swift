import Foundation
import Security
import OmniCore

struct LocalIdentity: Identifiable {
    let id = UUID()
    let reference: SecIdentity
    let certificate: SecCertificate
    let metadata: CertificateMetadata
}
@MainActor enum IdentityInspector {
    /// Read-only discovery limited by iOS to OmniSign's accessible Keychain identities.
    static func discover() throws -> [LocalIdentity] {
        let query: [String: Any] = [kSecClass as String: kSecClassIdentity, kSecReturnRef as String: true,
                                   kSecMatchLimit as String: kSecMatchLimitAll, kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw SecureStoreError(code: status) }
        guard let identities = result as? [SecIdentity], identities.count <= 50 else { throw OmniError.limitsExceeded }
        return try identities.map { identity in
            var certificate: SecCertificate?
            let status = SecIdentityCopyCertificate(identity, &certificate)
            guard status == errSecSuccess else { throw SecureStoreError(code: status) }
            guard let certificate else { throw OmniError.invalidCertificate }
            let metadata = try CertificateMetadata(der: SecCertificateCopyData(certificate) as Data)
            return LocalIdentity(reference: identity, certificate: certificate, metadata: metadata)
        }
    }
    /// Explicit owner-triggered challenge. This does not establish Apple chain/profile eligibility or export a key.
    static func proveOwnership(_ identity: LocalIdentity) throws -> Bool {
        guard identity.metadata.validity() == .valid else { throw OmniError.certificateExpired }
        var privateKey: SecKey?
        let status = SecIdentityCopyPrivateKey(identity.reference, &privateKey)
        guard status == errSecSuccess else { throw SecureStoreError(code: status) }
        guard let privateKey else { throw OmniError.privateKeyUnavailable }
        return try challenge(privateKey: privateKey, certificate: identity.certificate)
    }
    static func challenge(privateKey: SecKey, certificate: SecCertificate) throws -> Bool {
        guard let publicKey = SecCertificateCopyKey(certificate) else { throw OmniError.invalidCertificate }
        let algorithms: [SecKeyAlgorithm] = [.rsaSignatureMessagePKCS1v15SHA256, .ecdsaSignatureMessageX962SHA256]
        guard let algorithm = algorithms.first(where: { SecKeyIsAlgorithmSupported(privateKey, .sign, $0) && SecKeyIsAlgorithmSupported(publicKey, .verify, $0) }) else { throw OmniError.unsupportedKeyAlgorithm }
        var bytes = [UInt8](repeating: 0, count: 32)
        let randomStatus = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard randomStatus == errSecSuccess else { throw SecureStoreError(code: randomStatus) }
        let challenge = Data(bytes)
        var error: Unmanaged<CFError>?
        defer { if let error { _ = error.takeRetainedValue() } }
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, challenge as CFData, &error) else { throw OmniError.keyOperationDenied }
        // Discard underlying descriptions: a crypto backend can include sensitive context.
        return SecKeyVerifySignature(publicKey, algorithm, challenge as CFData, signature, nil)
    }
}
