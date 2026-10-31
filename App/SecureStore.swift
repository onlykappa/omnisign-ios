import Foundation
import Security
import OmniCore

struct SecureStoreError: Error {
    let code: OSStatus
}
struct SecureStore {
    private let service: String
    init(service: String = "org.omnisign.local") { self.service = service }
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
    func read(key: String) throws -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw SecureStoreError(code: status) }
        guard let data = result as? Data else { throw OmniError.corruptedState }
        return data
    }
    func contains(_ key: String) -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key, kSecReturnData as String: false]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }
    func inspectCertificate(_ data: Data) throws -> String {
        let metadata = try CertificateMetadata(der: data)
        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else { throw OmniError.invalidCertificate }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust else { throw OmniError.unavailable }
        // Basic X.509 trust is not Apple development authorization or proof of private-key access.
        let networkStatus = SecTrustSetNetworkFetchAllowed(trust, false)
        guard networkStatus == errSecSuccess else { throw SecureStoreError(code: networkStatus) }
        let trustStatus = SecTrustEvaluateWithError(trust, nil) ? "Basic X.509 trust accepted" : "Basic X.509 trust not established"
        let expiration = ISO8601DateFormatter().string(from: metadata.notAfter)
        let units = metadata.subjectOrganizationalUnits.joined(separator: ", ")
        return "\(metadata.validity().rawValue.capitalized) · expires \(expiration)\nSubject OU (unverified): \(units.isEmpty ? "Absent" : units)\nDevelopment marker: \(metadata.hasDevelopmentMarker ? "Present; not proof of trust" : "Absent")\n\(trustStatus); Apple development eligibility and private-key ownership unverified"
    }
}
