import Foundation
import Security
import OmniCore

struct SecureStoreError: Error {
    let code: OSStatus
}
struct SecureStore {
    private let service = "org.omnisign.local"
    func save(_ data: Data, key: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key]
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = query; attributes.forEach { item[$0.key] = $0.value }
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw SecureStoreError(code: addStatus) }
        } else if status != errSecSuccess { throw SecureStoreError(code: status) }
    }
    // Deletes only a named item in OmniSign's private generic-password service; no certificate API.
    func removeLocalItem(key: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SecureStoreError(code: status) }
    }
    func contains(_ key: String) -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key, kSecReturnData as String: false]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }
    func inspectCertificate(_ data: Data) throws -> String {
        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else { throw OmniError.invalidProfile }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust else { throw OmniError.unavailable }
        // Basic X.509 trust is not Apple development authorization or proof of private-key access.
        SecTrustSetNetworkFetchAllowed(trust, false)
        return SecTrustEvaluateWithError(trust, nil) ? "X.509 trust accepted; signing eligibility unverified" : "X.509 trust not established"
    }
}
