// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import XCTest
import CodeSignKit
import DisposableSigningSupport

final class PKCS12SecurityTests: XCTestCase {
    /// All material is newly generated and destroyed locally; no owner assets or hardcoded passwords.
    func authenticatedFixture(encrypt: Bool, digest: String = "SHA256", iterations: Int = 2048,
                              cipher: String = "AES-256-CBC") throws -> (Data, String) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let raw = root.appendingPathComponent("raw.p12"), cert = root.appendingPathComponent("cert.der")
        let pem = root.appendingPathComponent("cert.pem"), key = root.appendingPathComponent("key.pem")
        let output = root.appendingPathComponent("protected.p12"), passwordFile = root.appendingPathComponent("password")
        let synthetic = try SyntheticIdentityFactory.generate(), password = UUID().uuidString
        try synthetic.ephemeralPKCS12.write(to: raw)
        try synthetic.certificateDER.write(to: cert)
        try Data(password.utf8).write(to: passwordFile)
        let brew = "/opt/homebrew/opt/openssl@3/bin/openssl"
        let executable = FileManager.default.isExecutableFile(atPath: brew) ? brew : "/usr/bin/openssl"
        func run(_ args: [String]) throws {
            let process = Process(); process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = args
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw FixtureError.generation }
        }
        try run(["x509", "-inform", "DER", "-in", cert.path, "-out", pem.path])
        try run(["pkcs12", "-in", raw.path, "-passin", "pass:", "-nodes", "-nocerts", "-out", key.path])
        // NONE isolates password-integrity verification from accidental decryption failures.
        let args = ["pkcs12", "-export", "-inkey", key.path, "-in", pem.path, "-out", output.path,
                    "-passout", "file:" + passwordFile.path, "-macalg", digest, "-iter", String(iterations),
                    "-keypbe", encrypt ? cipher : "NONE", "-certpbe", encrypt ? cipher : "NONE"]
        try run(args)
        return (try Data(contentsOf: output), password)
    }
    func testPasswordIntegrityIsRequiredEvenForUnencryptedBags() throws {
        let (data, password) = try authenticatedFixture(encrypt: false)
        XCTAssertNotNil(try PKCS12Parser(p12Data: data, password: password).rsaPrivateKey)
        XCTAssertThrowsError(try PKCS12Parser(p12Data: data, password: UUID().uuidString))
        let root = try XCTUnwrap(ASN1Helper.parseTLV(from: data))
        let children = ASN1Helper.parseSequenceChildren(from: root.value)
        let mac = ASN1Helper.parseSequenceChildren(from: children[2].value)
        let digestInfo = ASN1Helper.parseSequenceChildren(from: mac[0].value)
        let digest = digestInfo[1].value
        let range = try XCTUnwrap(data.range(of: digest))
        var tampered = data; tampered[range.lowerBound] ^= 1
        XCTAssertThrowsError(try PKCS12Parser(p12Data: tampered, password: password))
    }
    func testIndependentEncryptedPBES2AndSHA1MACAreAccepted() throws {
        for digest in ["SHA256", "SHA1"] {
            let (data, password) = try authenticatedFixture(encrypt: true, digest: digest)
            let parsed = try PKCS12Parser(p12Data: data, password: password)
            XCTAssertEqual(parsed.leafCertificate?.subjectPublicKeyInfoDER, parsed.rsaPrivateKey?.publicKey.derRepresentation)
        }
    }
    func testExcessiveMACWorkAndOversizedOrTrailingDERAreRejected() throws {
        let (data, password) = try authenticatedFixture(encrypt: false, iterations: 100_001)
        XCTAssertThrowsError(try PKCS12Parser(p12Data: data, password: password))
        XCTAssertThrowsError(try PKCS12Parser(p12Data: Data(repeating: 0, count: 262_145)))
        XCTAssertThrowsError(try PKCS12Parser(p12Data: data + Data([0]), password: password))
    }
    func testUnauthenticatedSyntheticPFXNeedsExplicitOptInAndMatchingKey() throws {
        let first = try SyntheticIdentityFactory.generate(), second = try SyntheticIdentityFactory.generate()
        XCTAssertThrowsError(try PKCS12Parser(p12Data: first.ephemeralPKCS12))
        let parsedSecond = try PKCS12Parser(p12Data: second.ephemeralPKCS12, allowUnauthenticatedSynthetic: true)
        let mismatched = try PKCS12Builder.build(certificateDER: first.certificateDER,
                                                privateKeyDER: parsedSecond.privateKeyDER)
        XCTAssertThrowsError(try PKCS12Parser(p12Data: mismatched, allowUnauthenticatedSynthetic: true))
    }
    func testCertificateBagOrderCannotSelectAnUnrelatedIdentityOrDuplicateMatch() throws {
        let first = try SyntheticIdentityFactory.generate(), second = try SyntheticIdentityFactory.generate()
        let parsed = try PKCS12Parser(p12Data: second.ephemeralPKCS12, allowUnauthenticatedSynthetic: true)
        let wrongFirst = try PKCS12Builder.build(certificateDER: first.certificateDER, privateKeyDER: parsed.privateKeyDER)
        func contents(_ pfx: Data) throws -> Data {
            let outer = try XCTUnwrap(ASN1Helper.parseTLV(from: pfx))
            let fields = ASN1Helper.parseSequenceChildren(from: outer.value)
            let ci = ASN1Helper.parseSequenceChildren(from: fields[1].value)
            let octets = try XCTUnwrap(ASN1Helper.parseTLV(from: ci[1].value))
            return try XCTUnwrap(ASN1Helper.parseTLV(from: octets.value)).value
        }
        func appendCertificate(_ certificate: Data, to original: Data) throws -> Data {
            let certOnly = try PKCS12Builder.build(certificateDER: certificate, privateKeyDER: nil)
            var items = try contents(original); items.append(try contents(certOnly))
            let safe = ASN1Helper.sequence(items)
            var ci = ASN1Helper.oidData
            ci.append(ASN1Helper.contextual(0, content: ASN1Helper.octetString(safe), constructed: true))
            var outer = ASN1Helper.integer(3); outer.append(ASN1Helper.sequence(ci))
            return ASN1Helper.sequence(outer)
        }
        let reordered = try appendCertificate(second.certificateDER, to: wrongFirst)
        let selected = try PKCS12Parser(p12Data: reordered, allowUnauthenticatedSynthetic: true)
        XCTAssertEqual(selected.leafCertificate?.rawDER, second.certificateDER)
        XCTAssertEqual(selected.intermediateCertificates.count, 1)
        let duplicate = try appendCertificate(second.certificateDER, to: reordered)
        XCTAssertThrowsError(try PKCS12Parser(p12Data: duplicate, allowUnauthenticatedSynthetic: true))
    }
    func testPBES2AES128AndMinimalIntegrityIterationAreSupported() throws {
        let (data, password) = try authenticatedFixture(encrypt: true, iterations: 1, cipher: "AES-128-CBC")
        XCTAssertNotNil(try PKCS12Parser(p12Data: data, password: password).rsaPrivateKey)
    }
    enum FixtureError: Error { case generation }
}
