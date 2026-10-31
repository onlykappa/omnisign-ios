import Foundation

public enum FailureSource: String, Codable, Sendable {
    case appleAuthentication, appleCertificate, appleProvisioning, pairing, localTransport, download, inspection, refresh
}
public enum FailureSignal: String, Codable, Sendable {
    case unspecified, twoFactorRequired, sessionExpired, anisetteUnavailable, malformedResponse, rateLimited, securityRestriction,
         identityUnavailable, profileRejected, pairingExpired, networkUnavailable, interrupted
}
public struct FailureAssessment: Equatable, Sendable {
    public let category: DiagnosticCategory
    public let signal: FailureSignal
    public let knownCode: Bool
    public let automaticRecoveryPermitted: Bool
    public static func assess(source: FailureSource, code: Int? = nil, httpStatus: Int? = nil, signal: FailureSignal = .unspecified) -> Self {
        let category: DiagnosticCategory
        switch source {
        case .appleAuthentication: category = .authentication
        case .appleCertificate: category = .certificate
        case .appleProvisioning: category = .provisioning
        case .pairing: category = .pairing
        case .localTransport, .download: category = .transport
        case .inspection: category = .inspection
        case .refresh: category = .refresh
        }
        let known = (source == .appleAuthentication && [-80045, -80046].contains(code ?? 0)) || (source == .appleCertificate && code == 7460)
        let resolved: FailureSignal = httpStatus == 429 ? .rateLimited : signal
        let sensitive: Set<FailureSignal> = [.twoFactorRequired, .sessionExpired, .anisetteUnavailable, .malformedResponse, .rateLimited, .securityRestriction, .identityUnavailable, .profileRejected, .pairingExpired]
        let recovery = source != .appleAuthentication && source != .appleCertificate && source != .appleProvisioning && !sensitive.contains(resolved) && (resolved == .networkUnavailable || resolved == .interrupted)
        return Self(category: category, signal: resolved, knownCode: known, automaticRecoveryPermitted: recovery)
    }
}
public struct EvidenceRetryBudget: Codable, Sendable {
    private var strategies: Set<RecoveryStrategy> = []
    public init() {}
    public var attempts: Int { strategies.count }
    /// This helper executes nothing. It must not authorize destructive operations or bypass runtime gates.
    public mutating func permit(_ strategy: RecoveryStrategy, assessment: FailureAssessment, destructive: Bool = false, safelyResumable: Bool = false) -> Bool {
        guard assessment.automaticRecoveryPermitted, !destructive, strategies.count < 5, !strategies.contains(strategy) else { return false }
        switch strategy {
        case .networkBackoff: guard [.transport, .refresh].contains(assessment.category) else { return false }
        case .reconnectTransport: guard assessment.category == .transport else { return false }
        case .revalidatePairing: guard assessment.category == .pairing else { return false }
        case .recheckProvisioning: return false // No automatic provisioning mutations before a reviewed backend.
        case .resumeTransfer: guard assessment.category == .transport, assessment.signal == .interrupted, safelyResumable else { return false }
        }
        strategies.insert(strategy); return true
    }
}
