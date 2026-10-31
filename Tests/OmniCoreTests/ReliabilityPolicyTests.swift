import XCTest
@testable import OmniCore

final class ReliabilityPolicyTests: XCTestCase {
    func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
    func fixture() -> URL { Bundle.module.url(forResource: "valid", withExtension: "ipa", subdirectory: "Fixtures")! }
    func testJournalCompletesOnlyPersistedInspection() async throws {
        let d = try directory(); defer { try? FileManager.default.removeItem(at: d) }
        let journal = try OperationJournal(directory: d), library = try Library(directory: d.appendingPathComponent("IPAs"))
        let id = try await journal.begin()
        try await journal.advance(id, to: .inspecting)
        let result = try library.importIPA(fixture())
        try await journal.advance(id, to: .verifying)
        try await journal.completeInspection(id, app: result.id, library: library)
        let reopened = try OperationJournal(directory: d)
        let snapshot = await reopened.snapshot()
        let record = try XCTUnwrap(snapshot.first)
        XCTAssertEqual(record.result, .completed); XCTAssertEqual(record.app, result.id)
        XCTAssertEqual(record.attempt, 1); XCTAssertGreaterThanOrEqual(record.elapsed(), 0)
    }
    func testRestartPreservesStageAndNeverResumes() async throws {
        let d = try directory(); defer { try? FileManager.default.removeItem(at: d) }
        let journal = try OperationJournal(directory:d)
        let id = try await journal.begin(); try await journal.advance(id, to:.inspecting)
        let restarted = try OperationJournal(directory:d)
        let snapshot = await restarted.snapshot()
        XCTAssertEqual(snapshot.first?.result,.interrupted)
        XCTAssertEqual(snapshot.first?.interruptedStage,.inspecting)
        XCTAssertEqual(snapshot.first?.diagnostic?.reason,.interrupted)
        do { try await restarted.advance(id,to:.verifying); XCTFail("Restart must not resume") } catch { XCTAssertEqual(error as? OmniError,.invalidTransition) }
    }
    func testMutationRecordsStayBlockedEvenWithExistingIPA() async throws {
        let d = try directory(); defer { try? FileManager.default.removeItem(at:d) }
        let journal = try OperationJournal(directory:d), library = try Library(directory:d.appendingPathComponent("IPAs"))
        let app = try library.importIPA(fixture())
        for kind in WorkKind.allCases where kind != .inspection {
            let id = try await journal.begin(kind)
            do { try await journal.completeInspection(id, app:app.id, library:library); XCTFail("Cannot convert blocked mutation into success") } catch { XCTAssertEqual(error as? OmniError,.invalidTransition) }
        }
        let records = await journal.snapshot()
        XCTAssertTrue(records.allSatisfy { $0.result == .blocked && $0.diagnostic?.reason == .unavailable })
    }
    func testInvalidTransitionAndMissingPackageCannotComplete() async throws {
        let d = try directory(); defer { try? FileManager.default.removeItem(at:d) }
        let journal = try OperationJournal(directory:d), library = try Library(directory:d.appendingPathComponent("IPAs"))
        let id = try await journal.begin()
        do { try await journal.advance(id,to:.completed); XCTFail("No skipped stages") } catch { XCTAssertEqual(error as? OmniError,.invalidTransition) }
        try await journal.advance(id,to:.inspecting); try await journal.advance(id,to:.verifying)
        do { try await journal.completeInspection(id, app:UUID(), library:library); XCTFail("No invented completion") } catch { XCTAssertEqual(error as? OmniError,.corruptedState) }
        let records = await journal.snapshot(); XCTAssertEqual(records.first?.result,.running)
    }
    func testTamperedDiagnosticCannotBeExportedAsRedacted() throws {
        let event = Diagnostic(category: .authentication)
        var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(event)) as! [String: Any]
        object["message"] = "sessionToken=synthetic-secret"
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try JSONDecoder().decode(Diagnostic.self, from: data))
    }
    func testCorruptJournalFailsWithoutOverwriting() throws {
        let d = try directory(); defer { try? FileManager.default.removeItem(at:d) }
        let file = d.appendingPathComponent("operations.json"), data = Data("{invalid".utf8)
        try data.write(to:file)
        XCTAssertThrowsError(try OperationJournal(directory:d))
        XCTAssertEqual(try Data(contentsOf:file),data)
    }
    func testRedactedJournalSchemaHasNoFreeFormSecrets() async throws {
        let d = try directory(); defer { try? FileManager.default.removeItem(at:d) }
        let journal = try OperationJournal(directory:d); let id = try await journal.begin()
        try await journal.fail(id,category:.inspection,code:7460,reason:.unsafeArchive)
        let data = try await journal.exportRedacted()
        let object = try JSONSerialization.jsonObject(with:data) as! [[String:Any]]
        let diagnostic = object[0]["diagnostic"] as! [String:Any]
        XCTAssertEqual(Set(diagnostic.keys),Set(["id","date","category","code","operation","message","reason"]))
        XCTAssertEqual(diagnostic["code"] as? Int,7460)
        XCTAssertFalse(String(decoding:data,as:UTF8.self).contains("bundleID"))
    }
    func evidence(team: String = "TEAM", bundle: String = "org.app", version: String = "2.0", verified: Bool = true, groups: Set<String> = []) -> UpdateEvidence {
        UpdateEvidence(bundleID:bundle, team:team, version:version, keychainGroups:groups, signatureVerified:verified, profileVerified:verified, entitlementsVerified:verified)
    }
    func testUpdateDecisionNeverAssumesInventoryOrSignature() {
        XCTAssertEqual(SafeUpdatePolicy.evaluate(installed:nil,incoming:evidence()).disposition,.blocked)
        XCTAssertEqual(SafeUpdatePolicy.evaluate(installed:evidence(),incoming:evidence(team:"OTHER")).reasons,[.differentTeam])
        XCTAssertEqual(SafeUpdatePolicy.evaluate(installed:evidence(),incoming:evidence(bundle:"org.other")).disposition,.blocked)
        XCTAssertEqual(SafeUpdatePolicy.evaluate(installed:evidence(),incoming:evidence(verified:false)).disposition,.blocked)
    }
    func testUpdateWarnsAboutDataGroupsAndDowngrade() {
        let decision = SafeUpdatePolicy.evaluate(installed:evidence(),incoming:evidence(version:"1.0",groups:["TEAM.group"]))
        XCTAssertEqual(decision.disposition,.caution)
        XCTAssertTrue(decision.reasons.contains(.dataPreservationUnproven))
        XCTAssertTrue(decision.reasons.contains(.keychainAccessMayChange))
        XCTAssertTrue(decision.reasons.contains(.possibleDowngrade))
        XCTAssertEqual(SafeUpdatePolicy.evaluate(installed:evidence(),incoming:evidence(),dataPreservationDemonstrated:true).disposition,.compatible)
    }
    func testVersionComparisonIsNumericAndBounded() {
        XCTAssertEqual(SafeUpdatePolicy.compareVersions("1.10","1.9"),.orderedDescending)
        XCTAssertEqual(SafeUpdatePolicy.compareVersions("001.02.0","1.2"),.orderedSame)
        XCTAssertEqual(SafeUpdatePolicy.compareVersions(String(repeating:"9",count:100),"2"),.orderedDescending)
        for invalid in ["1..0","beta","","1.☃","1.-1"] { XCTAssertNil(SafeUpdatePolicy.compareVersions(invalid,"1")) }
    }
    func testFailureClassificationRetainsBackendAndStopsSecuritySensitiveRecovery() {
        for code in [-80045,-80046] {
            let auth = FailureAssessment.assess(source:.appleAuthentication,code:code,httpStatus:503,signal:.networkUnavailable)
            XCTAssertTrue(auth.knownCode); XCTAssertFalse(auth.automaticRecoveryPermitted)
            XCTAssertFalse(FailureAssessment.assess(source:.download,code:code).knownCode)
        }
        XCTAssertTrue(FailureAssessment.assess(source:.appleCertificate,code:7460).knownCode)
        XCTAssertFalse(FailureAssessment.assess(source:.localTransport,code:7460).knownCode)
        for signal in [FailureSignal.twoFactorRequired,.sessionExpired,.anisetteUnavailable,.malformedResponse,.securityRestriction,.rateLimited,.identityUnavailable] {
            XCTAssertFalse(FailureAssessment.assess(source:.localTransport,signal:signal).automaticRecoveryPermitted)
        }
        XCTAssertFalse(FailureAssessment.assess(source:.download,httpStatus:429,signal:.networkUnavailable).automaticRecoveryPermitted)
    }
    func testRetryBudgetIsDistinctDurableAndNeverDestructive() throws {
        let transient = FailureAssessment.assess(source:.localTransport,signal:.networkUnavailable)
        var budget = EvidenceRetryBudget()
        XCTAssertFalse(budget.permit(.networkBackoff,assessment:transient,destructive:true))
        XCTAssertTrue(budget.permit(.networkBackoff,assessment:transient))
        budget = try JSONDecoder().decode(EvidenceRetryBudget.self,from:JSONEncoder().encode(budget))
        XCTAssertFalse(budget.permit(.networkBackoff,assessment:transient))
        XCTAssertFalse(budget.permit(.reconnectTransport,assessment:.assess(source:.appleAuthentication,httpStatus:503,signal:.networkUnavailable)))
        XCTAssertLessThanOrEqual(budget.attempts,5)
    }
}
