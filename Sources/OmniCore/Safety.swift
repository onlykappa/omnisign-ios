import Foundation

public enum DiagnosticCategory: String, Codable, CaseIterable, Sendable {
    case inspection, authentication, certificate, provisioning, pairing, installation, refresh, transport, unknown
    public static func classify(code: Int?, httpStatus: Int? = nil, stage: DiagnosticCategory) -> DiagnosticCategory {
        if stage == .authentication, httpStatus == 503 || httpStatus == 429 { return .authentication }
        // These codes vary by backend; retain the originating stage instead of inventing meanings.
        if [-80045, -80046, 7460].contains(code ?? 0) { return stage }
        return stage
    }
}
public struct Diagnostic: Codable, Identifiable, Sendable {
    public let id: UUID
    public let date: Date
    public let category: DiagnosticCategory
    public let code: Int?
    public let httpStatus: Int?
    public let operation: UUID
    public let message: String
    public let reason: OmniError?
    private static let safeMessage = "Operation stopped. Review the category, numeric code and feasibility gate."
    private enum CodingKeys: String, CodingKey { case id, date, category, code, httpStatus, operation, message, reason }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id); date = try c.decode(Date.self, forKey: .date)
        category = try c.decode(DiagnosticCategory.self, forKey: .category)
        code = try c.decodeIfPresent(Int.self, forKey: .code); httpStatus = try c.decodeIfPresent(Int.self, forKey: .httpStatus)
        operation = try c.decode(UUID.self, forKey: .operation); reason = try c.decodeIfPresent(OmniError.self, forKey: .reason)
        guard try c.decode(String.self, forKey: .message) == Self.safeMessage,
              date >= Date(timeIntervalSince1970: 0), date <= Date.distantFuture else { throw OmniError.corruptedState }
        message = Self.safeMessage
    }
    public init(category: DiagnosticCategory, code: Int? = nil, httpStatus: Int? = nil, operation: UUID = UUID(), reason: OmniError? = nil) {
        id = UUID(); date = Date(); self.category = .classify(code: code, httpStatus: httpStatus, stage: category)
        self.code = code; self.httpStatus = httpStatus; self.operation = operation; self.reason = reason
        // Never accept free-form backend text: it can contain pairing material, tokens or identifiers.
        message = Self.safeMessage
    }
}
public struct RecoveryBudget {
    private var seen = Set<String>()
    public init() {}
    public mutating func permit(strategy: String, category: DiagnosticCategory, httpStatus: Int? = nil, securityRestriction: Bool = false) -> Bool {
        guard category != .authentication, !securityRestriction, httpStatus != 429, httpStatus != 503,
              !strategy.isEmpty, seen.count < 5, !seen.contains(strategy) else { return false }
        seen.insert(strategy); return true
    }
}
public struct ProfileSummary: Equatable, Sendable {
    public let team: String
    public let appIdentifier: String
    public let expiration: Date
    public let creationDate: Date?
    public let deviceCount: Int
    /// Decoded plist inspection only. This does NOT validate a CMS signature or Apple trust chain.
    public init(decodedPlist: Data, now: Date = Date(), allowExpiredForInspection: Bool = false) throws {
        guard let p = try PropertyListSerialization.propertyList(from: decodedPlist, format: nil) as? [String: Any],
              let teams = p["TeamIdentifier"] as? [String], teams.count == 1, let team = teams.first, !team.isEmpty, team.allSatisfy({ $0.isASCII && $0.isLetter || $0.isNumber && $0.isASCII }),
              let ent = p["Entitlements"] as? [String: Any], let app = ent["application-identifier"] as? String,
              let expiration = p["ExpirationDate"] as? Date, allowExpiredForInspection || expiration > now,
              app.hasPrefix(team + "."),
              IdentifierRules.bundle(app.hasSuffix(".*") ? String(app.dropLast(2)) : app) else { throw OmniError.invalidProfile }
        let creation = p["CreationDate"] as? Date
        guard creation == nil || expiration > creation!, allowExpiredForInspection || creation == nil || creation! <= now else { throw OmniError.invalidProfile }
        self.team = team; appIdentifier = app; self.expiration = expiration; creationDate = creation
        deviceCount = (p["ProvisionedDevices"] as? [String])?.count ?? 0
    }
    public func permits(bundleID: String, team: String, now: Date = Date()) -> Bool {
        guard expiration > now, creationDate == nil || creationDate! <= now, team == self.team, IdentifierRules.bundle(bundleID) else { return false }
        let expected = team + "." + bundleID
        if appIdentifier.hasSuffix(".*") { return expected.hasPrefix(String(appIdentifier.dropLast())) }
        return appIdentifier == expected
    }
}
public enum EntitlementPolicy {
    // Deliberately conservative: wildcards and nested capabilities need a reviewed backend.
    public static func compatible(requested: [String: String], allowed: [String: String]) -> Bool {
        requested.allSatisfy { allowed[$0.key] == $0.value }
    }
}
public enum PairingInspector {
    public static func validate(_ data: Data) throws {
        guard data.count <= 2_097_152,
              let p = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let host = p["HostID"] as? String, !host.isEmpty,
              let system = p["SystemBUID"] as? String, !system.isEmpty else { throw OmniError.invalidPairing }
        for key in ["HostCertificate", "HostPrivateKey", "RootCertificate", "RootPrivateKey", "DeviceCertificate"] {
            guard let bytes = p[key] as? Data, !bytes.isEmpty else { throw OmniError.invalidPairing }
        }
    }
}
public enum OperationKind: String, CaseIterable, Sendable { case authenticate, sign, install, update, refresh }
public struct ExperimentalEngine: Sendable {
    public init() {}
    public func perform(_ kind: OperationKind) async throws -> Never { throw OmniError.unavailable }
}
public enum InstallationPreflight {
    public static func check(oldBundle: String, newBundle: String, oldTeam: String, newTeam: String, signatureVerified: Bool, transportVerified: Bool) throws {
        guard oldBundle == newBundle, oldTeam == newTeam, !oldBundle.isEmpty, !oldTeam.isEmpty else { throw OmniError.incompatible }
        guard signatureVerified, transportVerified else { throw OmniError.unavailable }
        // Compatibility alone is not evidence of data preservation.
    }
}
