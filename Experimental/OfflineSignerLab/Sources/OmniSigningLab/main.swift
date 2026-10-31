// SPDX-License-Identifier: AGPL-3.0-only
// Offline disposable-fixture experiment. Not linked into OmniSign's application.
import Foundation
import CodeSignKit
import IndependentCMSVerifier
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
    guard parsed.rsaPrivateKey != nil, parsed.leafCertificate != nil else { throw LabFailure.inputRejected }
    try CodeSigner.sign(appPath: root.path, keyData: identity, password: password, teamID: "OMNILAB123", entitlementProvider: { _ in "" }, progress: {})
    print("Experimental signing command completed; independent verification is REQUIRED. This is not Apple authorization or an installation result.")
} catch {
    // Deliberately exclude backend descriptions, paths, PKCS#12 data and passphrase from logs.
    FileHandle.standardError.write(Data("Disposable signing experiment failed; inspect synthetic fixtures locally.\n".utf8)); exit(1)
}
