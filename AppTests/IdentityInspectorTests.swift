import XCTest
import Security
import OmniCore
@testable import OmniSign

final class IdentityInspectorTests: XCTestCase {
    @MainActor func testGeneratedIdentityProvesMatchingKeyAndRejectsOtherCertificate() throws {
        let bundle = Bundle(for: Self.self)
        guard let p12 = bundle.url(forResource: "fixture", withExtension: "p12"),
              let passwordFile = bundle.url(forResource: "fixture-password", withExtension: nil) else {
            XCTFail("Generate disposable test identity with scripts/generate-test-identity.py before XcodeGen")
            throw OmniError.unavailable
        }
        let password = try String(contentsOf: passwordFile)
        var imported: CFArray?
        let status = SecPKCS12Import(try Data(contentsOf:p12) as CFData, [kSecImportExportPassphrase as String:password] as CFDictionary, &imported)
        XCTAssertEqual(status,errSecSuccess)
        let items = try XCTUnwrap(imported as? [[String:Any]])
        let raw = try XCTUnwrap(items.first?[kSecImportItemIdentity as String])
        XCTAssertEqual(CFGetTypeID(raw as CFTypeRef),SecIdentityGetTypeID())
        let reference = raw as! SecIdentity
        var certificate: SecCertificate?, privateKey: SecKey?
        XCTAssertEqual(SecIdentityCopyCertificate(reference,&certificate),errSecSuccess)
        XCTAssertEqual(SecIdentityCopyPrivateKey(reference,&privateKey),errSecSuccess)
        let cert = try XCTUnwrap(certificate), key = try XCTUnwrap(privateKey)
        defer {
            // Exact generated test references only. Never remove broad identity/key/certificate classes.
            SecItemDelete([kSecClass as String:kSecClassKey,kSecValueRef as String:key] as CFDictionary)
            SecItemDelete([kSecClass as String:kSecClassCertificate,kSecValueRef as String:cert] as CFDictionary)
        }
        let metadata = try CertificateMetadata(der:SecCertificateCopyData(cert) as Data)
        let identity = LocalIdentity(reference:reference,certificate:cert,metadata:metadata)
        XCTAssertTrue(try IdentityInspector.proveOwnership(identity))
        XCTAssertFalse(metadata.hasDevelopmentMarker)
        let unrelatedDER = try Data(contentsOf:XCTUnwrap(bundle.url(forResource:"synthetic-certificate",withExtension:"der")))
        let unrelated = try XCTUnwrap(SecCertificateCreateWithData(nil,unrelatedDER as CFData))
        XCTAssertFalse(try IdentityInspector.challenge(privateKey:key,certificate:unrelated))
    }
}
