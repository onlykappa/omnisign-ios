import Foundation

public enum UpdateDisposition: String, Codable, Sendable { case compatible, caution, blocked }
public enum UpdateReason: String, Codable, Sendable {
    case missingInstalledEvidence, invalidIdentity, differentBundleID, differentTeam, unverifiedSignature, unverifiedProvisioning,
         unverifiedEntitlements, keychainAccessMayChange, sharedContainersMayChange, dataPreservationUnproven, possibleDowngrade, unknownVersion, evidenceConsistent
}
public struct UpdateEvidence: Sendable {
    public let bundleID: String
    public let team: String
    public let version: String
    public let keychainGroups: Set<String>
    public let appGroups: Set<String>
    public let signatureVerified: Bool
    public let profileVerified: Bool
    public let entitlementsVerified: Bool
    public init(bundleID: String, team: String, version: String, keychainGroups: Set<String> = [], appGroups: Set<String> = [], signatureVerified: Bool = false, profileVerified: Bool = false, entitlementsVerified: Bool = false) {
        self.bundleID = bundleID; self.team = team; self.version = version; self.keychainGroups = keychainGroups; self.appGroups = appGroups
        self.signatureVerified = signatureVerified; self.profileVerified = profileVerified; self.entitlementsVerified = entitlementsVerified
    }
}
public struct UpdateDecision: Equatable, Sendable {
    public let disposition: UpdateDisposition
    public let reasons: [UpdateReason]
}
public enum SafeUpdatePolicy {
    /// Policy only: caller assertions are not independently verified evidence or authorization to install.
    public static func evaluate(installed: UpdateEvidence?, incoming: UpdateEvidence, dataPreservationDemonstrated: Bool = false) -> UpdateDecision {
        guard let installed else { return UpdateDecision(disposition: .blocked, reasons: [.missingInstalledEvidence]) }
        guard IdentifierRules.bundle(installed.bundleID), IdentifierRules.bundle(incoming.bundleID), !installed.team.isEmpty, !incoming.team.isEmpty else { return UpdateDecision(disposition: .blocked, reasons: [.invalidIdentity]) }
        guard installed.bundleID == incoming.bundleID else { return UpdateDecision(disposition: .blocked, reasons: [.differentBundleID]) }
        guard installed.team == incoming.team else { return UpdateDecision(disposition: .blocked, reasons: [.differentTeam]) }
        var blocked: [UpdateReason] = []
        if !installed.signatureVerified || !incoming.signatureVerified { blocked.append(.unverifiedSignature) }
        if !installed.profileVerified || !incoming.profileVerified { blocked.append(.unverifiedProvisioning) }
        if !installed.entitlementsVerified || !incoming.entitlementsVerified { blocked.append(.unverifiedEntitlements) }
        guard blocked.isEmpty else { return UpdateDecision(disposition: .blocked, reasons: blocked) }
        var warnings: [UpdateReason] = []
        if installed.keychainGroups != incoming.keychainGroups { warnings.append(.keychainAccessMayChange) }
        if installed.appGroups != incoming.appGroups { warnings.append(.sharedContainersMayChange) }
        if !dataPreservationDemonstrated { warnings.append(.dataPreservationUnproven) }
        if let comparison = compareVersions(incoming.version, installed.version) {
            if comparison == .orderedAscending { warnings.append(.possibleDowngrade) }
        } else { warnings.append(.unknownVersion) }
        return warnings.isEmpty ? UpdateDecision(disposition: .compatible, reasons: [.evidenceConsistent]) : UpdateDecision(disposition: .caution, reasons: warnings)
    }
    public static func compareVersions(_ a: String, _ b: String) -> ComparisonResult? {
        func parse(_ string: String) -> [String]? {
            guard !string.isEmpty, string.utf8.count <= 128 else { return nil }
            let parts = string.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy { (48...57).contains($0) } }) else { return nil }
            return parts.map { let trim = $0.drop(while: { $0 == "0" }); return trim.isEmpty ? "0" : String(trim) }
        }
        guard let lhs = parse(a), let rhs = parse(b) else { return nil }
        for i in 0..<max(lhs.count, rhs.count) {
            let x = i < lhs.count ? lhs[i] : "0", y = i < rhs.count ? rhs[i] : "0"
            if x.count != y.count { return x.count < y.count ? .orderedAscending : .orderedDescending }
            if x != y { return x < y ? .orderedAscending : .orderedDescending }
        }
        return .orderedSame
    }
}
