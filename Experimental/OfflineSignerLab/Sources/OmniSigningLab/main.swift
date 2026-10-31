// SPDX-License-Identifier: AGPL-3.0-only
// Offline disposable-fixture experiment. Not linked into OmniSign's application.
import Foundation
import CodeSignKit
import IndependentCMSVerifier
import DisposableSigningSupport
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

enum LabFailure: Error { case inputRejected }
func bounded(_ file: URL, limit: Int) throws -> Data {
    let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
    let data = try handle.read(upToCount: limit + 1) ?? Data()
    guard data.count <= limit else { throw LabFailure.inputRejected }
    return data
}
// This intentionally cannot sign the owner's Kodi or KappaForge identifiers.
guard CommandLine.arguments.count == 4 else {
    FileHandle.standardError.write(Data("Usage: omnisign-lab <disposable.app> <synthetic-identity.p12> <password-file>\n".utf8)); exit(2)
}
do {
    if CommandLine.arguments[1] == "--generate-fixture-identity" {
        let pfx = URL(fileURLWithPath:CommandLine.arguments[2]), certificate = URL(fileURLWithPath:CommandLine.arguments[3])
        umask(0o077)
        guard pfx.standardizedFileURL != certificate.standardizedFileURL, !FileManager.default.fileExists(atPath:pfx.path), !FileManager.default.fileExists(atPath:certificate.path) else { throw LabFailure.inputRejected }
        let identity = try SyntheticIdentityFactory.generate()
        try identity.ephemeralPKCS12.write(to:pfx,options:.atomic)
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:pfx.path)
        try identity.certificateDER.write(to:certificate,options:.atomic)
        print("Generated a disposable non-Apple test identity locally; no key material is logged. Unencrypted PFX is test-only and must remain in the ephemeral test directory.")
        exit(0)
    }
    if CommandLine.arguments[1] == "--verify-code" {
        let binary = try bounded(URL(fileURLWithPath:CommandLine.arguments[2]),limit:16_777_216)
        var slots: [Int:Data] = [:]
        if CommandLine.arguments[3] != "-" {
            let bundle = URL(fileURLWithPath:CommandLine.arguments[3])
            slots[1] = try bounded(bundle.appendingPathComponent("Info.plist"),limit:2_097_152)
            let seal = bundle.appendingPathComponent("_CodeSignature/CodeResources")
            if FileManager.default.fileExists(atPath:seal.path) { slots[3] = try bounded(seal,limit:2_097_152) }
        }
        let result = try IndependentCodeVerifier.verify(binary:binary,externalSpecialSlots:slots)
        guard result.codeAndCMSMathematicallyVerified, !result.resourceFilesVerified, !result.canAuthorizeInstallation else { throw LabFailure.inputRejected }
        print("Independent Swift code-page/special-slot/CMS mathematics verified; resource-file coverage, Apple trust and installation remain unverified.")
        exit(0)
    }
    if CommandLine.arguments[1] == "--verify-cms" {
        let signature = try bounded(URL(fileURLWithPath: CommandLine.arguments[2]), limit: 2_097_152)
        let content = try bounded(URL(fileURLWithPath: CommandLine.arguments[3]), limit: 16_777_216)
        let proof = try IndependentCMSVerifier.verify(signature: signature, detachedContent: content)
        guard proof.signatureMathematicallyVerified, !proof.appleTrustVerified, !proof.canAuthorizeInstallation else { throw LabFailure.inputRejected }
        print("Independent Swift CMS mathematics verified; Apple trust, certificate time and installation authorization are not verified.")
        exit(0)
    }
    let root = URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL
    guard root.pathExtension == "app", root == root.resolvingSymlinksInPath(),
          let info = try PropertyListSerialization.propertyList(from: bounded(root.appendingPathComponent("Info.plist"), limit: 1_048_576), format: nil) as? [String: Any],
          info["CFBundleIdentifier"] as? String == "org.omnisign.lab" else { throw LabFailure.inputRejected }
    // Reject symlinked code/resources before calling the experimental recursive backend.
    guard let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isSymbolicLinkKey]) else { throw LabFailure.inputRejected }
    for case let url as URL in enumerator {
        guard try url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true else { throw LabFailure.inputRejected }
    }
    let identity = try bounded(URL(fileURLWithPath: CommandLine.arguments[2]), limit: 262_144)
    let passwordData = try bounded(URL(fileURLWithPath: CommandLine.arguments[3]), limit: 4096)
    guard let password = String(data: passwordData, encoding: .utf8)?.trimmingCharacters(in: .newlines), !password.isEmpty else { throw LabFailure.inputRejected }
    let parsed = try PKCS12Parser(p12Data: identity, password: password)
    guard parsed.rsaPrivateKey != nil, let leaf = parsed.leafCertificate,
          leaf.issuerDER == leaf.subjectDER, leaf.organizationalUnit == "OMNILAB123", leaf.commonName == "OmniSign Disposable Lab" else { throw LabFailure.inputRejected }
    try CodeSigner.sign(appPath: root.path, keyData: identity, password: password, teamID: "OMNILAB123", entitlementProvider: { _ in "" }, progress: {})
    print("Experimental signing command completed; independent verification is REQUIRED. This is not Apple authorization or an installation result.")
} catch {
    // Deliberately exclude backend descriptions, paths, PKCS#12 data and passphrase from logs.
    FileHandle.standardError.write(Data("Disposable signing experiment failed; inspect synthetic fixtures locally.\n".utf8)); exit(1)
}
