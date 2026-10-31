import Foundation

public enum PairingFormat: String, Codable, Sendable { case lockdown, remotePairing }
public struct PairingSchemaReport: Codable, Equatable, Sendable {
    public let format: PairingFormat
    public var cryptographicCompatibilityVerified: Bool { false }
    public var canAuthorizeTransport: Bool { false }
}
public enum PairingSchemaInspector {
    /// Plist field/type inspection only. Key relationships, device identity and live pairing are not verified.
    public static func inspect(_ data: Data) throws -> PairingSchemaReport {
        guard data.count <= 2_097_152 else { throw OmniError.limitsExceeded }
        guard let object = try PropertyListSerialization.propertyList(from:data,format:nil) as? [String:Any], object.count <= 128 else { throw OmniError.invalidPairing }
        let remoteHints = ["private_key","public_key","identifier"].contains { object[$0] != nil }
        let lockdownHints = ["HostID","SystemBUID","RootPrivateKey"].contains { object[$0] != nil }
        guard !(remoteHints && lockdownHints) else { throw OmniError.ambiguousPairing }
        func text(_ name: String) -> Bool {
            guard let value = object[name] as? String else { return false }
            return !value.isEmpty && value.utf8.count <= 256 && !value.unicodeScalars.contains { $0.value < 32 }
        }
        func bytes(_ name: String, maximum: Int = 65_536) -> Bool {
            guard let value = object[name] as? Data else { return false }
            return !value.isEmpty && value.count <= maximum
        }
        if remoteHints {
            guard text("identifier"), bytes("private_key"), bytes("public_key") else { throw OmniError.invalidPairing }
            return PairingSchemaReport(format:.remotePairing)
        }
        guard lockdownHints, ["HostID","SystemBUID","UDID","WiFiMACAddress"].allSatisfy(text),
              ["HostCertificate","HostPrivateKey","RootCertificate","RootPrivateKey","DeviceCertificate"].allSatisfy({ bytes($0) }),
              bytes("EscrowBag",maximum:1_048_576) else { throw OmniError.invalidPairing }
        return PairingSchemaReport(format:.lockdown)
    }
}
