import Foundation

public enum WorkKind: String, Codable, CaseIterable, Sendable { case inspection, authentication, signing, installation, update, refresh }
public enum WorkStage: String, Codable, Sendable {
    case preparing, inspecting, validating, signing, connecting, installing, verifying, completed, failed, interrupted, blocked
}
public enum WorkResult: String, Codable, Sendable { case running, completed, failed, interrupted, blocked }
public enum RecoveryStrategy: String, Codable, CaseIterable, Sendable {
    case networkBackoff, reconnectTransport, revalidatePairing, recheckProvisioning, resumeTransfer
}
public struct WorkRecord: Codable, Identifiable, Sendable {
    public let id: UUID
    public let kind: WorkKind
    public internal(set) var app: UUID?
    public internal(set) var stage: WorkStage
    public let startedAt: Date
    public internal(set) var updatedAt: Date
    public internal(set) var finishedAt: Date?
    public let attempt: Int
    public internal(set) var diagnostic: Diagnostic?
    public internal(set) var interruptedStage: WorkStage?
    public internal(set) var result: WorkResult
    public func elapsed(at now: Date = Date()) -> TimeInterval { max(0, (finishedAt ?? now).timeIntervalSince(startedAt)) }
    func validate() throws {
        guard attempt == 1, startedAt >= Date(timeIntervalSince1970: 0), updatedAt <= Date.distantFuture, updatedAt >= startedAt,
              diagnostic == nil || diagnostic?.operation == id else { throw OmniError.corruptedState }
        if let finishedAt { guard finishedAt >= startedAt, finishedAt <= Date.distantFuture else { throw OmniError.corruptedState } }
        if kind != .inspection {
            guard result == .blocked, stage == .blocked, finishedAt != nil, diagnostic?.reason == .unavailable else { throw OmniError.corruptedState }
            return
        }
        switch result {
        case .running: guard [.preparing, .inspecting, .verifying].contains(stage), finishedAt == nil else { throw OmniError.corruptedState }
        case .completed: guard stage == .completed, app != nil, finishedAt != nil, diagnostic == nil else { throw OmniError.corruptedState }
        case .failed: guard stage == .failed, finishedAt != nil, diagnostic != nil else { throw OmniError.corruptedState }
        case .interrupted: guard stage == .interrupted, interruptedStage.map({ [.preparing, .inspecting, .verifying].contains($0) }) == true, finishedAt != nil, diagnostic?.reason == .interrupted else { throw OmniError.corruptedState }
        case .blocked: throw OmniError.corruptedState
        }
    }
}

/// Passive durable inspection history. It cannot execute, retry or certify signing/device operations.
public actor OperationJournal {
    private struct Document: Codable { let version: Int; var records: [WorkRecord] }
    private let url: URL
    private var records: [WorkRecord]
    public init(directory: URL, now: Date = Date()) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        url = directory.appendingPathComponent("operations.json")
        var loaded: [WorkRecord] = []
        if FileManager.default.fileExists(atPath: url.path) {
            let doc = try JSONDecoder().decode(Document.self, from: BoundedFile.read(url, maximumBytes: 2_097_152))
            guard doc.version == 1, doc.records.count <= 256, Set(doc.records.map(\.id)).count == doc.records.count else { throw OmniError.corruptedState }
            loaded = doc.records
            for record in loaded { try record.validate() }
        }
        var recovered = false
        for index in loaded.indices where loaded[index].result == .running {
            recovered = true
            loaded[index].interruptedStage = loaded[index].stage
            loaded[index].stage = .interrupted; loaded[index].result = .interrupted
            loaded[index].updatedAt = max(now, loaded[index].startedAt); loaded[index].finishedAt = loaded[index].updatedAt
            loaded[index].diagnostic = Diagnostic(category: .inspection, operation: loaded[index].id, reason: .interrupted)
        }
        if recovered { try Self.write(loaded, to: url) }
        records = loaded
    }
    private static func write(_ records: [WorkRecord], to url: URL) throws {
        for record in records { try record.validate() }
        let data = try JSONEncoder().encode(Document(version: 1, records: records))
        guard data.count <= 2_097_152 else { throw OmniError.limitsExceeded }
        #if os(iOS)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: url, options: .atomic)
        #endif
    }
    private func commit(_ candidate: [WorkRecord]) throws {
        try Self.write(candidate, to: url)
        records = candidate
    }
    public func snapshot() -> [WorkRecord] { records.sorted { $0.startedAt > $1.startedAt } }
    public func exportRedacted() throws -> Data { try JSONEncoder().encode(records) }
    @discardableResult public func begin(_ kind: WorkKind = .inspection, at now: Date = Date()) throws -> UUID {
        var candidate = records
        if candidate.count >= 256 {
            guard let oldest = candidate.indices.filter({ candidate[$0].result != .running }).min(by: { candidate[$0].startedAt < candidate[$1].startedAt }) else { throw OmniError.limitsExceeded }
            candidate.remove(at: oldest) // Bounded local history only; no IPA or installed application is deleted.
        }
        let id = UUID(), blocked = kind != .inspection
        candidate.append(WorkRecord(id: id, kind: kind, app: nil, stage: blocked ? .blocked : .preparing,
                                    startedAt: now, updatedAt: now, finishedAt: blocked ? now : nil, attempt: 1,
                                    diagnostic: blocked ? Diagnostic(category: .unknown, operation: id, reason: .unavailable) : nil,
                                    interruptedStage: nil, result: blocked ? .blocked : .running))
        try commit(candidate); return id
    }
    public func advance(_ id: UUID, to stage: WorkStage, at now: Date = Date()) throws {
        guard let index = records.firstIndex(where: { $0.id == id }), records[index].kind == .inspection, records[index].result == .running,
              (records[index].stage == .preparing && stage == .inspecting) || (records[index].stage == .inspecting && stage == .verifying) else { throw OmniError.invalidTransition }
        var candidate = records
        candidate[index].stage = stage; candidate[index].updatedAt = max(now, candidate[index].updatedAt)
        try commit(candidate)
    }
    public func completeInspection(_ id: UUID, app: UUID, library: Library, at now: Date = Date()) throws {
        guard let index = records.firstIndex(where: { $0.id == id }), records[index].kind == .inspection,
              records[index].result == .running, records[index].stage == .verifying else { throw OmniError.invalidTransition }
        guard try library.load().contains(where: { $0.id == app }) else { throw OmniError.corruptedState }
        var candidate = records
        candidate[index].app = app; candidate[index].stage = .completed; candidate[index].result = .completed
        candidate[index].updatedAt = max(now, candidate[index].updatedAt); candidate[index].finishedAt = candidate[index].updatedAt
        try commit(candidate)
    }
    public func fail(_ id: UUID, category: DiagnosticCategory, code: Int? = nil, httpStatus: Int? = nil, reason: OmniError? = nil, at now: Date = Date()) throws {
        guard let index = records.firstIndex(where: { $0.id == id }), records[index].result == .running else { throw OmniError.invalidTransition }
        var candidate = records
        candidate[index].stage = .failed; candidate[index].result = .failed
        candidate[index].updatedAt = max(now, candidate[index].updatedAt); candidate[index].finishedAt = candidate[index].updatedAt
        candidate[index].diagnostic = Diagnostic(category: category, code: code, httpStatus: httpStatus, operation: id, reason: reason)
        try commit(candidate)
    }
}
