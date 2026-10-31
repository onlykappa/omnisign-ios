//
//  PKCS12Parser.swift
//  CodeSignKit
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Foundation
import Crypto
import CryptoExtras
import SwiftASN1

public final class PKCS12Parser {

    public private(set) var leafCertificate: X509Certificate?
    public private(set) var intermediateCertificates: [X509Certificate] = []
    public private(set) var privateKeyDER: Data?
    public private(set) var rsaPrivateKey: _RSA.Signing.PrivateKey?

    public init(p12Data: Data, password: String = "", allowUnauthenticatedSynthetic: Bool = false) throws {
        guard p12Data.count <= 262_144, password.utf8.count <= 4096 else {
            throw CodeSignerError.certificateError("PKCS12 input limit exceeded")
        }
        // Validate canonical bounded DER before the permissive upstream helpers touch input lengths.
        _ = try DER.parse(Array(p12Data))
        try parse(data: p12Data, password: password, allowUnauthenticatedSynthetic: allowUnauthenticatedSynthetic)
    }

    private func parse(data: Data, password: String, allowUnauthenticatedSynthetic: Bool) throws {
        // PFX: SEQUENCE { version INTEGER, authSafe ContentInfo, macData MacData OPTIONAL }
        guard let pfxTLV = ASN1Helper.parseTLV(from: data), pfxTLV.tag == 0x30 else {
            throw CodeSignerError.certificateError("Invalid PKCS#12 structure (not an ASN.1 SEQUENCE)")
        }

        let pfxChildren = ASN1Helper.parseSequenceChildren(from: pfxTLV.value)
        guard (2...3).contains(pfxChildren.count), pfxChildren[0].tag == 0x02, pfxChildren[0].value == Data([3]) else {
            throw CodeSignerError.certificateError("Truncated PKCS#12 PFX structure")
        }

        // authSafe ContentInfo: SEQUENCE { contentType OBJECT IDENTIFIER, content [0] EXPLICIT ANY }
        let authSafeTLV = pfxChildren[1]
        let authSafeChildren = ASN1Helper.parseSequenceChildren(from: authSafeTLV.value)
        guard authSafeTLV.tag == 0x30, authSafeChildren.count == 2, authSafeChildren[1].tag == 0xA0 else {
            throw CodeSignerError.certificateError("Invalid authSafe ContentInfo")
        }

        let contentTypeData = authSafeChildren[0].rawDER
        guard let contentWrappedTLV = ASN1Helper.parseTLV(from: authSafeChildren[1].value) else {
            throw CodeSignerError.certificateError("Missing content in authSafe")
        }

        guard contentTypeData == ASN1Helper.oidData, contentWrappedTLV.tag == 0x04,
              contentWrappedTLV.totalLength == authSafeChildren[1].value.count else {
            throw CodeSignerError.certificateError("Unsupported authenticated safe container")
        }
        let authenticatedSafeBytes = contentWrappedTLV.value
        if pfxChildren.count == 3 {
            try verifyMAC(pfxChildren[2].rawDER, authenticatedSafe: authenticatedSafeBytes, password: password)
        } else if !allowUnauthenticatedSynthetic {
            throw CodeSignerError.certificateError("Unauthenticated PKCS12 is disabled")
        }

        // AuthenticatedSafe: SEQUENCE OF ContentInfo
        let contentInfos: [(tag: UInt8, value: Data, rawDER: Data)]
        if let authSafeSeq = ASN1Helper.parseTLV(from: authenticatedSafeBytes), authSafeSeq.tag == 0x30 {
            contentInfos = ASN1Helper.parseSequenceChildren(from: authSafeSeq.value)
        } else {
            contentInfos = ASN1Helper.parseSequenceChildren(from: authenticatedSafeBytes)
        }

        guard contentInfos.count <= 16 else { throw CodeSignerError.certificateError("Too many PKCS12 content sections") }
        var bagCount = 0
        for safeContentCI in contentInfos {
            guard safeContentCI.tag == 0x30 else { continue }
            let ciChildren = ASN1Helper.parseSequenceChildren(from: safeContentCI.value)
            guard ciChildren.count >= 2 else { continue }

            let ciType = ciChildren[0].rawDER
            let ciContentWrapped = ciChildren[1]

            let safeBagsBytes: Data
            if ciType == ASN1Helper.oidData {
                // [0] EXPLICIT OCTET STRING containing SafeContents SEQUENCE
                if let octetTLV = ASN1Helper.parseTLV(from: ciContentWrapped.value) {
                    safeBagsBytes = octetTLV.value
                } else {
                    safeBagsBytes = ciContentWrapped.value
                }
            } else if ciType == ASN1Helper.oidEncryptedData {
                safeBagsBytes = try decryptEncryptedContentInfo(ciContentWrapped.value, password: password)
            } else {
                continue
            }

            // OCTET STRING and decrypted plaintext were opaque to the outer DER check.
            _ = try DER.parse(Array(safeBagsBytes))
            // SafeContents: SEQUENCE OF SafeBag
            let safeBags: [(tag: UInt8, value: Data, rawDER: Data)]
            if let scSeq = ASN1Helper.parseTLV(from: safeBagsBytes), scSeq.tag == 0x30 {
                safeBags = ASN1Helper.parseSequenceChildren(from: scSeq.value)
            } else {
                safeBags = ASN1Helper.parseSequenceChildren(from: safeBagsBytes)
            }

            bagCount += safeBags.count
            guard bagCount <= 32 else { throw CodeSignerError.certificateError("Too many PKCS12 bags") }
            for bag in safeBags {
                guard bag.tag == 0x30 else { continue }
                try processSafeBag(bag.value, password: password)
            }
        }

        guard let key = self.rsaPrivateKey, key.keySizeInBits >= 2048, key.keySizeInBits <= 4096 else {
            throw CodeSignerError.certificateError("Supported private key is missing")
        }
        let certificates = (leafCertificate.map { [$0] } ?? []) + intermediateCertificates
        let matching = certificates.filter { $0.subjectPublicKeyInfoDER == key.publicKey.derRepresentation }
        guard matching.count == 1 else { throw CodeSignerError.certificateError("Ambiguous or mismatched key and certificate") }
        leafCertificate = matching[0]
        intermediateCertificates = certificates.filter { $0.rawDER != matching[0].rawDER }
        // Explicit unauthenticated mode is only for our newly generated synthetic test identity.
        if pfxChildren.count == 2 {
            guard allowUnauthenticatedSynthetic, matching[0].issuerDER == matching[0].subjectDER,
                  matching[0].commonName == "OmniSign Disposable Lab", matching[0].organizationalUnit == "OMNILAB123" else {
                throw CodeSignerError.certificateError("Unauthenticated non-synthetic identity rejected")
            }
        }
    }

    /// RFC7292 password-integrity mode; only SHA1/SHA256 and bounded iteration/salt sizes.
    private func verifyMAC(_ der: Data, authenticatedSafe: Data, password: String) throws {
        guard let outer = ASN1Helper.parseTLV(from: der), outer.tag == 0x30 else {
            throw CodeSignerError.certificateError("Invalid PKCS12 integrity container")
        }
        let mac = ASN1Helper.parseSequenceChildren(from: outer.value)
        guard (2...3).contains(mac.count), mac[0].tag == 0x30, mac[1].tag == 0x04,
              (8...64).contains(mac[1].value.count) else { throw CodeSignerError.certificateError("Invalid PKCS12 integrity fields") }
        let info = ASN1Helper.parseSequenceChildren(from: mac[0].value)
        guard info.count == 2, info[0].tag == 0x30, info[1].tag == 0x04 else { throw CodeSignerError.certificateError("Invalid MAC digest info") }
        let algorithm = ASN1Helper.parseSequenceChildren(from: info[0].value)
        guard (1...2).contains(algorithm.count), algorithm[0].tag == 0x06,
              algorithm.count == 1 || (algorithm[1].tag == 0x05 && algorithm[1].value.isEmpty) else { throw CodeSignerError.certificateError("Invalid MAC algorithm") }
        let sha256 = algorithm[0].rawDER == ASN1Helper.encodeOID("2.16.840.1.101.3.4.2.1")
        guard sha256 || algorithm[0].rawDER == ASN1Helper.encodeOID("1.3.14.3.2.26") else { throw CodeSignerError.certificateError("Unsupported PKCS12 MAC digest") }
        let rounds: Int
        if mac.count == 3 {
            guard mac[2].tag == 0x02 else { throw CodeSignerError.certificateError("Invalid MAC iterations") }
            rounds = try parseInteger(from: mac[2].value)
        } else { rounds = 1 }
        guard (1...100_000).contains(rounds), info[1].value.count == (sha256 ? 32 : 20) else { throw CodeSignerError.certificateError("MAC work limit exceeded") }
        // Both supported hashes have a 64-byte block; one digest block suffices for their MAC key.
        var passwordBytes = Data()
        for unit in password.utf16 { passwordBytes.append(UInt8(unit >> 8)); passwordBytes.append(UInt8(unit & 255)) }
        passwordBytes.append(contentsOf: [0, 0])
        func expanded(_ value: Data) -> Data {
            let size = 64 * ((value.count + 63) / 64)
            return Data((0..<size).map { value[$0 % value.count] })
        }
        var material = Data(repeating: 3, count: 64)
        material.append(expanded(mac[1].value)); material.append(expanded(passwordBytes))
        var digest = sha256 ? Data(SHA256.hash(data: material)) : Data(Insecure.SHA1.hash(data: material))
        if rounds > 1 { for _ in 2...rounds { digest = sha256 ? Data(SHA256.hash(data: digest)) : Data(Insecure.SHA1.hash(data: digest)) } }
        let key = SymmetricKey(data: digest)
        let valid = sha256 ? HMAC<SHA256>.isValidAuthenticationCode(info[1].value, authenticating: authenticatedSafe, using: key)
                           : HMAC<Insecure.SHA1>.isValidAuthenticationCode(info[1].value, authenticating: authenticatedSafe, using: key)
        guard valid else { throw CodeSignerError.certificateError("PKCS12 authentication failed") }
    }

    private func processSafeBag(_ bagValue: Data, password: String) throws {
        // SafeBag: SEQUENCE { bagId OBJECT IDENTIFIER, bagValue [0] EXPLICIT ANY, bagAttributes SET OF PKCS12Attribute OPTIONAL }
        let bagChildren = ASN1Helper.parseSequenceChildren(from: bagValue)
        guard bagChildren.count >= 2 else { return }

        let bagId = bagChildren[0].rawDER
        let bagContentWrapped = bagChildren[1]

        if bagId == ASN1Helper.oidCertBag {
            // CertBag: SEQUENCE { certId OBJECT IDENTIFIER, certValue [0] EXPLICIT OCTET STRING }
            guard let certBagTLV = ASN1Helper.parseTLV(from: bagContentWrapped.value), certBagTLV.tag == 0x30 else { return }
            let certBagChildren = ASN1Helper.parseSequenceChildren(from: certBagTLV.value)
            if certBagChildren.count >= 2 {
                guard let certOctetTLV = ASN1Helper.parseTLV(from: certBagChildren[1].value) else { return }
                _ = try DER.parse(Array(certOctetTLV.value))
                if let cert = X509Certificate(der: certOctetTLV.value) {
                    if self.leafCertificate == nil {
                        self.leafCertificate = cert
                    } else {
                        self.intermediateCertificates.append(cert)
                    }
                }
            }
        } else if bagId == ASN1Helper.oidPkcs8ShroudedKeyBag {
            // EncryptedPrivateKeyInfo: SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, encryptedData OCTET STRING }
            let decryptedKeyDER = try decryptEncryptedPrivateKeyInfo(bagContentWrapped.value, password: password)
            self.privateKeyDER = decryptedKeyDER
            try loadRSAPrivateKey(from: decryptedKeyDER)
        } else if bagId == ASN1Helper.oidKeyBag {
            // Unencrypted PrivateKeyInfo
            self.privateKeyDER = bagContentWrapped.value
            try loadRSAPrivateKey(from: bagContentWrapped.value)
        }
    }

    private func loadRSAPrivateKey(from der: Data) throws {
        guard rsaPrivateKey == nil else { throw CodeSignerError.certificateError("Multiple PKCS12 private keys are unsupported") }
        _ = try DER.parse(Array(der))
        // Try PKCS#8 or PKCS#1 RSAPrivateKey
        if let key = try? _RSA.Signing.PrivateKey(derRepresentation: der) {
            self.rsaPrivateKey = key
            return
        }

        // If der is PrivateKeyInfo, extract the inner privateKey OCTET STRING (PKCS#1)
        if let tlv = ASN1Helper.parseTLV(from: der), tlv.tag == 0x30 {
            let children = ASN1Helper.parseSequenceChildren(from: tlv.value)
            for child in children {
                if child.tag == 0x04 { // OCTET STRING containing RSAPrivateKey
                    if let key = try? _RSA.Signing.PrivateKey(derRepresentation: child.value) {
                        self.rsaPrivateKey = key
                        return
                    }
                }
            }
        }

        throw CodeSignerError.certificateError("Unsupported private key format in PKCS#12 (only RSA is supported)")
    }

    // PKCS#12 / PBES Decryption
    private func decryptEncryptedContentInfo(_ contentData: Data, password: String) throws -> Data {
        // contentData can be EncryptedData: SEQUENCE { version INTEGER, encryptedContentInfo EncryptedContentInfo }
        // or directly EncryptedContentInfo: SEQUENCE { contentType OBJECT IDENTIFIER, contentEncryptionAlgorithm AlgorithmIdentifier, encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL }
        guard let tlv = ASN1Helper.parseTLV(from: contentData), tlv.tag == 0x30 else {
            throw CodeSignerError.certificateError("Invalid EncryptedData/EncryptedContentInfo")
        }
        let children = ASN1Helper.parseSequenceChildren(from: tlv.value)

        let eciValue: Data
        if children.count >= 2 && children[0].tag == 0x02 { // EncryptedData (version, encryptedContentInfo)
            eciValue = children[1].value
        } else {
            eciValue = tlv.value
        }

        let eciChildren = ASN1Helper.parseSequenceChildren(from: eciValue)
        guard eciChildren.count >= 3 else {
            throw CodeSignerError.certificateError("Invalid EncryptedContentInfo structure")
        }

        let algData = eciChildren[1].rawDER
        var encryptedBytes = eciChildren[2].value
        if eciChildren[2].tag == 0xA0 || eciChildren[2].tag == 0x24 {
            if let innerTLV = ASN1Helper.parseTLV(from: encryptedBytes), innerTLV.tag == 0x04 {
                encryptedBytes = innerTLV.value
            }
        }
        return try decryptData(encryptedBytes, algorithmDER: algData, password: password)
    }

    private func decryptEncryptedPrivateKeyInfo(_ epkiData: Data, password: String) throws -> Data {
        // EncryptedPrivateKeyInfo: SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, encryptedData OCTET STRING }
        guard let tlv = ASN1Helper.parseTLV(from: epkiData), tlv.tag == 0x30 else {
            throw CodeSignerError.certificateError("Invalid EncryptedPrivateKeyInfo")
        }
        let children = ASN1Helper.parseSequenceChildren(from: tlv.value)
        guard children.count >= 2 else {
            throw CodeSignerError.certificateError("Truncated EncryptedPrivateKeyInfo")
        }

        let algData = children[0].rawDER
        var encryptedBytes = children[1].value
        if children[1].tag == 0xA0 || children[1].tag == 0x24 {
            if let innerTLV = ASN1Helper.parseTLV(from: encryptedBytes), innerTLV.tag == 0x04 {
                encryptedBytes = innerTLV.value
            }
        }
        return try decryptData(encryptedBytes, algorithmDER: algData, password: password)
    }

    private func decryptData(_ cipher: Data, algorithmDER: Data, password: String) throws -> Data {
        guard let algTLV = ASN1Helper.parseTLV(from: algorithmDER), algTLV.tag == 0x30 else {
            throw CodeSignerError.certificateError("Invalid AlgorithmIdentifier")
        }
        let algChildren = ASN1Helper.parseSequenceChildren(from: algTLV.value)
        guard !algChildren.isEmpty else {
            throw CodeSignerError.certificateError("Missing algorithm in AlgorithmIdentifier")
        }

        let algOID = algChildren[0].rawDER

        if algOID == ASN1Helper.oidPBES2 {
            // PBES2: SEQUENCE { keyDerivationFunc (PBKDF2), encryptionScheme (AES-CBC) }
            guard algChildren.count >= 2 else {
                throw CodeSignerError.certificateError("Invalid PBES2 parameters")
            }
            let pbes2Params = ASN1Helper.parseSequenceChildren(from: algChildren[1].value)
            guard pbes2Params.count >= 2 else {
                throw CodeSignerError.certificateError("Truncated PBES2 parameters")
            }

            // 1. Key Derivation (PBKDF2)
            let pbkdf2Children = ASN1Helper.parseSequenceChildren(from: pbes2Params[0].value)
            guard pbkdf2Children.count >= 2 else {
                throw CodeSignerError.certificateError("Invalid PBKDF2 parameters")
            }
            let pbkdf2ParamChildren = ASN1Helper.parseSequenceChildren(from: pbkdf2Children[1].value)
            guard pbkdf2ParamChildren.count >= 2 else {
                throw CodeSignerError.certificateError("Invalid PBKDF2 inner parameters")
            }

            let salt = pbkdf2ParamChildren[0].value
            let rounds = try parseInteger(from: pbkdf2ParamChildren[1].value)
            guard pbkdf2Children[0].rawDER == ASN1Helper.oidPBKDF2,
                  pbkdf2ParamChildren[0].tag == 0x04, (8...64).contains(salt.count),
                  pbkdf2ParamChildren[1].tag == 0x02, (1...100_000).contains(rounds),
                  pbkdf2ParamChildren.count <= 4 else { throw CodeSignerError.certificateError("Unsupported PBKDF2 parameters or work limit") }

            // PBKDF2 defaults to HMAC-SHA1; optional keyLength shifts the PRF position.
            var prfOID: Data? = ASN1Helper.encodeOID("1.2.840.113549.2.7")
            var next = 2
            var requestedKeyLength: Int?
            if next < pbkdf2ParamChildren.count, pbkdf2ParamChildren[next].tag == 0x02 {
                requestedKeyLength = try parseInteger(from: pbkdf2ParamChildren[next].value); next += 1
            }
            if next < pbkdf2ParamChildren.count {
                let field = pbkdf2ParamChildren[next]
                let prf = ASN1Helper.parseSequenceChildren(from: field.value)
                guard field.tag == 0x30, (1...2).contains(prf.count), prf[0].tag == 0x06,
                      prf.count == 1 || (prf[1].tag == 0x05 && prf[1].value.isEmpty) else { throw CodeSignerError.certificateError("Invalid PBKDF2 PRF") }
                prfOID = prf[0].rawDER; next += 1
            }
            guard next == pbkdf2ParamChildren.count,
                  prfOID == ASN1Helper.encodeOID("1.2.840.113549.2.7") || prfOID == ASN1Helper.encodeOID("1.2.840.113549.2.9") else {
                throw CodeSignerError.certificateError("Unsupported PBKDF2 PRF")
            }

            // 2. Encryption Scheme
            let encSchemeChildren = ASN1Helper.parseSequenceChildren(from: pbes2Params[1].value)
            guard encSchemeChildren.count >= 2 else {
                throw CodeSignerError.certificateError("Invalid encryption scheme parameters")
            }
            let encOID = encSchemeChildren[0].rawDER
            let iv = encSchemeChildren[1].value

            let keyLength: Int
            if encOID == ASN1Helper.oidAES256CBC {
                keyLength = 32
            } else if encOID == ASN1Helper.oidDesEde3Cbc {
                keyLength = 24
            } else if encOID == ASN1Helper.oidAES128CBC {
                keyLength = 16
            } else { throw CodeSignerError.certificateError("Unsupported PBES2 cipher") }
            guard requestedKeyLength == nil || requestedKeyLength == keyLength else { throw CodeSignerError.certificateError("PBKDF2 key length mismatch") }

            let pwdData = Data(password.utf8)
            let derivedKey = try derivePBKDF2Key(password: pwdData, salt: salt, rounds: rounds, keyLength: keyLength, prfOID: prfOID)

            if encOID == ASN1Helper.oidDesEde3Cbc {
                return try TripleDESCipher.decryptCBC(cipher: cipher, key: derivedKey, iv: iv)
            } else {
                let symmetricKey = SymmetricKey(data: derivedKey)
                let ivObj = try AES._CBC.IV(ivBytes: iv)
                return try AES._CBC.decrypt(cipher, using: symmetricKey, iv: ivObj, noPadding: false)
            }
        } else if algOID == ASN1Helper.oidPbeWithSHAAnd3KeyTripleDESCBC ||
                    algOID == ASN1Helper.oidPbeWithSHAAnd40BitRC2CBC {
            // PKCS#12 PBE
            guard algChildren.count >= 2 else {
                throw CodeSignerError.certificateError("Missing PKCS#12 PBE parameters")
            }
            let pbeParams = ASN1Helper.parseSequenceChildren(from: algChildren[1].value)
            guard pbeParams.count >= 2 else {
                throw CodeSignerError.certificateError("Truncated PKCS#12 PBE parameters")
            }
            let salt = pbeParams[0].value
            let rounds = try parseInteger(from: pbeParams[1].value)
            guard pbeParams[1].tag == 0x02, (1...100_000).contains(rounds), (8...64).contains(salt.count) else {
                throw CodeSignerError.certificateError("Legacy PBE work limit exceeded")
            }

            let is3DES = (algOID == ASN1Helper.oidPbeWithSHAAnd3KeyTripleDESCBC)
            let keyLength = is3DES ? 24 : 5
            let ivLength = 8

            let derivedKey = derivePKCS12Key(id: 1, password: password, salt: salt, rounds: rounds, length: keyLength)
            let derivedIV = derivePKCS12Key(id: 2, password: password, salt: salt, rounds: rounds, length: ivLength)

            if is3DES {
                return try TripleDESCipher.decryptCBC(cipher: cipher, key: derivedKey, iv: derivedIV)
            } else {
                return try RC2Cipher.decryptCBC(cipher: cipher, key: derivedKey, iv: derivedIV, effectiveKeyBits: 40)
            }
        }

        throw CodeSignerError.certificateError("Unsupported encryption algorithm in PKCS#12")
    }

    private func parseInteger(from data: Data) throws -> Int {
        guard !data.isEmpty, data.count <= 4, data.first! < 0x80 else { throw CodeSignerError.certificateError("Invalid bounded positive integer") }
        var val = 0
        for byte in data {
            val = (val << 8) | Int(byte)
        }
        return val
    }

    // PBKDF2 Derivation (SHA-256 or SHA-1)
    private func derivePBKDF2Key(password: Data, salt: Data, rounds: Int, keyLength: Int, prfOID: Data? = nil) throws -> Data {
        let isSHA1 = (prfOID == ASN1Helper.encodeOID("1.2.840.113549.2.7"))
        if isSHA1 {
            let hLen = 20
            let l = (keyLength + hLen - 1) / hLen
            var dk = Data()

            for i in 1...l {
                var counter = Data(count: 4)
                counter[0] = UInt8((i >> 24) & 0xFF)
                counter[1] = UInt8((i >> 16) & 0xFF)
                counter[2] = UInt8((i >> 8) & 0xFF)
                counter[3] = UInt8(i & 0xFF)

                let saltAndCounter = salt + counter
                let key = SymmetricKey(data: password)
                var u = Data(HMAC<Insecure.SHA1>.authenticationCode(for: saltAndCounter, using: key))
                var t = u

                if rounds > 1 {
                    for _ in 2...rounds {
                        u = Data(HMAC<Insecure.SHA1>.authenticationCode(for: u, using: key))
                        for k in 0..<hLen {
                            t[k] ^= u[k]
                        }
                    }
                }
                dk.append(t)
            }
            return dk.prefix(keyLength)
        } else {
            let hLen = 32
            let l = (keyLength + hLen - 1) / hLen
            var dk = Data()

            for i in 1...l {
                var counter = Data(count: 4)
                counter[0] = UInt8((i >> 24) & 0xFF)
                counter[1] = UInt8((i >> 16) & 0xFF)
                counter[2] = UInt8((i >> 8) & 0xFF)
                counter[3] = UInt8(i & 0xFF)

                let saltAndCounter = salt + counter
                let key = SymmetricKey(data: password)
                var u = Data(HMAC<SHA256>.authenticationCode(for: saltAndCounter, using: key))
                var t = u

                if rounds > 1 {
                    for _ in 2...rounds {
                        u = Data(HMAC<SHA256>.authenticationCode(for: u, using: key))
                        for k in 0..<hLen {
                            t[k] ^= u[k]
                        }
                    }
                }
                dk.append(t)
            }
            return dk.prefix(keyLength)
        }
    }

    // PKCS#12 KDF (RFC 7292 Appendix B)
    private func derivePKCS12Key(id: UInt8, password: String, salt: Data, rounds: Int, length: Int) -> Data {
        let v = 64 // SHA-1 block size
        let u = 20 // SHA-1 digest size

        let d = Data(repeating: id, count: v)

        // Password as UTF-16BE bytes including trailing null
        var pBytes = Data()
        for scalar in password.utf16 {
            pBytes.append(UInt8((scalar >> 8) & 0xFF))
            pBytes.append(UInt8(scalar & 0xFF))
        }
        pBytes.append(0x00)
        pBytes.append(0x00)

        // S' (salt extended to multiple of v)
        var sPrime = Data()
        if !salt.isEmpty {
            let sLen = v * ((salt.count + v - 1) / v)
            while sPrime.count < sLen {
                sPrime.append(salt)
            }
            sPrime = sPrime.prefix(sLen)
        }

        // P' (password extended to multiple of v)
        var pPrime = Data()
        if !pBytes.isEmpty {
            let pLen = v * ((pBytes.count + v - 1) / v)
            while pPrime.count < pLen {
                pPrime.append(pBytes)
            }
            pPrime = pPrime.prefix(pLen)
        }

        let iBlock = sPrime + pPrime
        let c = (length + u - 1) / u
        var derived = Data()

        var currentI = iBlock

        for _ in 1...c {
            var a = Data(Insecure.SHA1.hash(data: d + currentI))
            if rounds > 1 {
                for _ in 2...rounds {
                    a = Data(Insecure.SHA1.hash(data: a))
                }
            }

            derived.append(a)

            if derived.count >= length { break }

            // B = repeat(A, v)
            var b = Data()
            while b.count < v {
                b.append(a)
            }
            b = b.prefix(v)

            // For each v-byte block in currentI: Ij = (Ij + B + 1) mod 2^(8*v)
            let kBlocks = currentI.count / v
            for blockIdx in 0..<kBlocks {
                var carry: UInt32 = 1
                let blockStart = blockIdx * v
                let blockEnd = blockStart + v
                for j in stride(from: blockEnd - 1, through: blockStart, by: -1) {
                    let sum = UInt32(currentI[j]) + UInt32(b[j - blockStart]) + carry
                    currentI[j] = UInt8(sum & 0xFF)
                    carry = sum >> 8
                }
            }
        }

        return derived.prefix(length)
    }
}
