import Foundation
import UIKit
import SwiftUI
import UniformTypeIdentifiers
import OmniCore

struct HTTPFailure: Error { let status: Int }
final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
enum HTTPSDownloader {
    // A nonisolated async function performs streaming file IO away from the UI actor.
    static func download(_ url: URL, to temporary: URL) async throws {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30; config.timeoutIntervalForResource = 180
        let session = URLSession(configuration: config, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (bytes, response) = try await session.bytes(from: url)
        guard let http = response as? HTTPURLResponse else { throw OmniError.unavailable }
        guard http.statusCode == 200 else { throw HTTPFailure(status: http.statusCode) }
        guard response.expectedContentLength <= 1_073_741_824 else { throw OmniError.limitsExceeded }
        guard FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: [.protectionKey: FileProtectionType.complete]) else { throw OmniError.unavailable }
        let handle = try FileHandle(forWritingTo: temporary)
        defer { try? handle.close() }
        var count = 0, buffer = Data()
        for try await byte in bytes {
            try Task.checkCancellation()
            count += 1; guard count <= 1_073_741_824 else { throw OmniError.limitsExceeded }
            buffer.append(byte)
            if buffer.count >= 65_536 { try handle.write(contentsOf: buffer); buffer.removeAll(keepingCapacity: true) }
        }
        try handle.write(contentsOf: buffer); try handle.synchronize()
    }
}
@MainActor final class AppModel: ObservableObject {
    @Published var items: [Inspection] = []
    @Published var diagnostics: [Diagnostic] = []
    @Published var operations: [WorkRecord] = []
    @Published var diagnosticExport: URL?
    @Published var busy = false
    @Published var status = "Ready to inspect"
    @Published var pairing = "Not imported"
    @Published var pairingReplacementPending = false
    private var pendingPairingData: Data?
    private var pendingPairingFormat: PairingFormat?
    private let secureStore: SecureStore
    @Published var certificate = "Not inspected"
    @Published var certificateExpiration = "Unknown"
    @Published var profile = "No provisioning profile imported"
    @Published var identities: [LocalIdentity] = []
    @Published var identityStatus = "Not queried; no Apple account requests"
    @Published var identityProofs: [UUID: String] = [:]
    private(set) var library: Library?
    private(set) var journal: OperationJournal?
    init(secureStore: SecureStore = SecureStore(), dataDirectory: URL? = nil) {
        self.secureStore = secureStore
        do {
            let directory = try dataDirectory ?? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("Library", isDirectory: true)
            library = try Library(directory: directory)
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: directory.path)
            var values = URLResourceValues(); values.isExcludedFromBackup = true
            var protectedURL = directory; try protectedURL.setResourceValues(values)
            items = try library!.load()
            journal = try OperationJournal(directory: directory)
            do {
                if let stored = try secureStore.read(key: "pairing") {
                    let report = try PairingSchemaInspector.inspect(stored)
                    pairing = "Stored \(report.format.rawValue) schema; connection unverified"
                }
            } catch { pairing = "Stored pairing unavailable, incomplete or unsupported; connection unverified" }
            do {
                if let stored = try secureStore.read(key: "certificate") {
                    certificate = try secureStore.inspectCertificate(stored)
                    certificateExpiration = ISO8601DateFormatter().string(from: try CertificateMetadata(der: stored).notAfter)
                }
            } catch { certificate = "Stored certificate unavailable or invalid; signing disabled" }
            do {
                if let stored = try secureStore.read(key: "profile") { profile = Self.describeProfile(try ProfileEnvelope(cms: stored)) }
            } catch { profile = "Stored profile invalid or unavailable; signing blocked" }
            Task { await reloadOperations() }
        } catch { library = nil; journal = nil; status = "Library or history unavailable; imports disabled; existing files preserved" }
    }
    func record(_ category: DiagnosticCategory, error: Error? = nil) {
        diagnostics.append(Diagnostic(category: category, code: (error as? SecureStoreError).map { Int($0.code) }, httpStatus: (error as? HTTPFailure)?.status, reason: error as? OmniError))
        status = "Operation stopped; see Diagnostics"
    }
    func reloadOperations() async { if let journal { operations = await journal.snapshot() } }
    private func fail(_ id: UUID?, category: DiagnosticCategory, error: Error) async {
        record(category, error: error)
        guard let id, let journal else { return }
        do {
            try await journal.fail(id, category: category, code: (error as? SecureStoreError).map { Int($0.code) }, httpStatus: (error as? HTTPFailure)?.status, reason: error as? OmniError)
        } catch { status = "Operation stopped; history could not be saved; existing IPA files preserved" }
        await reloadOperations()
    }
    private func inspectAndPersist(_ source: URL, operation: UUID) async throws {
        guard let library, let journal else { throw OmniError.unavailable }
        try await journal.advance(operation, to: .inspecting); await reloadOperations(); status = "Inspecting…"
        let result = try await Task.detached { try library.importIPA(source) }.value
        try await journal.advance(operation, to: .verifying); await reloadOperations(); status = "Verifying persisted inspection…"
        try await journal.completeInspection(operation, app: result.id, library: library)
        items.append(result); await reloadOperations(); status = "Imported and inspected; signing unverified"
    }
    func importFile(_ url: URL, kind: String) async {
        guard !busy else { return }; busy = true; status = "Preparing import…"
        defer { busy = false }
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        var operation: UUID?
        do {
            if kind == "ipa" {
                guard let journal else { throw OmniError.unavailable }
                let id = try await journal.begin(); operation = id
                try await inspectAndPersist(url, operation: id)
            } else {
                let data = try BoundedFile.read(url, maximumBytes: 2_097_152)
                if kind == "pairing" {
                    let report = try PairingSchemaInspector.inspect(data)
                    if try secureStore.read(key: "pairing") != nil {
                        pendingPairingData = data; pendingPairingFormat = report.format
                        pairingReplacementPending = true; status = "Pairing schema inspected; replacement awaits explicit owner approval"
                    } else {
                        try secureStore.save(data, key: "pairing")
                        pairing = "Stored \(report.format.rawValue) schema; connection unverified"; status = "Pairing schema inspected; device compatibility unverified"
                    }
                } else if kind == "profile" {
                    let envelope = try ProfileEnvelope(cms: data)
                    try secureStore.save(data, key: "profile"); profile = Self.describeProfile(envelope)
                    status = "Provisioning profile inspected; CMS trust unverified"
                } else {
                    let summary = try secureStore.inspectCertificate(data)
                    try secureStore.save(data, key: "certificate"); certificate = summary
                    certificateExpiration = ISO8601DateFormatter().string(from: try CertificateMetadata(der: data).notAfter)
                    status = "Certificate inspected"
                }
            }
        } catch { await fail(operation, category: kind == "pairing" ? .pairing : kind == "certificate" ? .certificate : kind == "profile" ? .provisioning : .inspection, error: error) }
    }
    func download(_ string: String) async {
        guard !busy else { return }
        guard let url = URL(string: string), url.scheme == "https", url.user == nil, url.password == nil, url.host != nil else { record(.transport); return }
        busy = true; status = "Downloading untrusted source…"
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { busy = false; try? FileManager.default.removeItem(at: temporary) }
        var operation: UUID?
        do {
            guard let journal else { throw OmniError.unavailable }
            let id = try await journal.begin(); operation = id; await reloadOperations()
            try await HTTPSDownloader.download(url, to: temporary)
            try await inspectAndPersist(temporary, operation: id)
        } catch { await fail(operation, category: .transport, error: error) }
    }
    func cancelPairingReplacement() {
        pendingPairingData = nil; pendingPairingFormat = nil; pairingReplacementPending = false
        status = "Pairing replacement cancelled; previous credentials preserved"
    }
    func approvePairingReplacement() {
        defer { pendingPairingData = nil; pendingPairingFormat = nil; pairingReplacementPending = false }
        guard let data = pendingPairingData, let format = pendingPairingFormat else { return }
        do {
            try secureStore.save(data, key: "pairing")
            pairing = "Stored \(format.rawValue) schema; connection unverified"; status = "Pairing replaced with owner approval; device compatibility unverified"
        } catch { record(.pairing, error: error) }
    }
    private static func describeProfile(_ envelope: ProfileEnvelope) -> String {
        let summary = envelope.summary, now = Date()
        let state = summary.expiration <= now ? "Expired" : ((summary.creationDate ?? .distantPast) > now ? "Not yet valid" : "Time-valid metadata")
        return "\(envelope.profileName ?? "Unnamed profile")\n\(summary.appIdentifier)\nExpires \(ISO8601DateFormatter().string(from: summary.expiration)) · \(summary.deviceCount) listed devices\n\(state); CMS signature/Apple trust unverified; signing blocked"
    }
    func inspectLocalIdentities() {
        do {
            identities = try IdentityInspector.discover(); identityProofs = [:]
            identityStatus = identities.isEmpty ? "No identities accessible in OmniSign’s Keychain. A certificate alone cannot sign; no certificate requests were sent." : "Local identities discovered; Apple development eligibility and reuse remain unverified."
        } catch { identities = []; record(.certificate, error: error); identityStatus = "Identity lookup blocked; no automatic retry or certificate creation" }
    }
    func proveIdentity(_ identity: LocalIdentity) {
        do {
            identityProofs[identity.id] = try IdentityInspector.proveOwnership(identity) ? "Matching private key proved locally; Apple eligibility and app signing remain unverified" : "Private key does not match this certificate; reuse blocked"
        } catch { identityProofs[identity.id] = "Reuse blocked: " + ((error as? OmniError)?.rawValue ?? "private-key access unavailable; see numeric diagnostics"); record(.certificate, error: error) }
    }
    func prepareDiagnosticExport() async {
        do {
            guard let journal else { throw OmniError.unavailable }
            let data = try await journal.exportRedacted()
            let file = FileManager.default.temporaryDirectory.appendingPathComponent("OmniSign-redacted-history.json")
            try data.write(to: file, options: [.atomic, .completeFileProtection])
            diagnosticExport = file
        } catch { diagnosticExport = nil; record(.unknown, error: error) }
    }
}
@main struct OmniSignApp: App {
    @StateObject private var model = AppModel()
    var body: some Scene { WindowGroup { RootView().environmentObject(model).preferredColorScheme(.dark).tint(.purple) } }
}
struct RootView: View {
    @EnvironmentObject var model: AppModel
    @State private var importer = false
    @State private var kind = "ipa"
    @State private var downloadURL = ""
    @State private var downloadPrompt = false
    private func select(_ value: String) { guard !model.busy else { return }; kind = value; importer = true }
    var body: some View {
        TabView {
            NavigationStack {
                List {
                    Section {
                        Label("OmniSign · Experimental", systemImage: "signature").font(.title2.bold())
                        Text("Signing and device services are disabled pending validation.").foregroundStyle(.secondary)
                        Button { select("ipa") } label: { Label("Import IPA", systemImage: "plus.app.fill") }.buttonStyle(.borderedProminent).disabled(model.busy)
                        Text(model.status)
                        if model.busy { ProgressView() }
                    }
                    Section("This iPhone") {
                        LabeledContent("Device", value: UIDevice.current.model)
                        LabeledContent("OS", value: UIDevice.current.systemVersion)
                        LabeledContent("Signing", value: "Unavailable")
                        LabeledContent("Certificate expiry", value: model.certificateExpiration)
                        LabeledContent("Pairing", value: model.pairing)
                        LabeledContent("VPN / transport", value: "Not probed")
                        LabeledContent("Installed apps", value: "Unknown")
                        LabeledContent("Imported apps", value: "\(model.items.count)")
                        LabeledContent("Needs inspection", value: "\(model.items.count)")
                    }
                }.navigationTitle("Home")
            }.tabItem { Label("Home", systemImage: "house") }
            NavigationStack {
                List {
                    Section { Text("No verified installation inventory. Imported apps are shown below; they are not recorded as installed.") }
                    appRows
                }.navigationTitle("My Apps")
            }.tabItem { Label("My Apps", systemImage: "square.stack") }
            NavigationStack {
                List {
                    Button("Import from Files") { select("ipa") }.disabled(model.busy)
                    Button("Download from HTTPS URL…") { downloadPrompt = true }.disabled(model.busy)
                    appRows
                }.navigationTitle("IPA Library")
            }.tabItem { Label("Library", systemImage: "archivebox") }
            NavigationStack {
                List {
                    Section("Build and licenses") {
                        Text("V1 Experimental · device workflows unverified")
                        NavigationLink("Open-source notices") {
                            ScrollView { Text(Bundle.main.url(forResource: "THIRD_PARTY_NOTICES", withExtension: "md").flatMap { try? String(contentsOf: $0) } ?? "Notices unavailable").font(.caption).padding() }.navigationTitle("Licenses")
                        }
                    }
                    Section("Apple account") {
                        Text("Authentication disabled. No Apple credentials are requested or sent.")
                        Text("Existing certificate and accessible private key are required for reuse. Automatic revocation is prohibited.")
                    }
                    Section("Local inspection") {
                        Button("Import DER certificate") { select("certificate") }.disabled(model.busy)
                        Text(model.certificate)
                        Text("Imported DER validity dates and subject OU are metadata only. Apple development eligibility and private-key ownership remain unverified.")
                        Button("Import pairing plist for inspection") { select("pairing") }.disabled(model.busy)
                        Text(model.pairing)
                        Text("Pairing secrets are stored in this device’s Keychain. Source-traced Lockdown and Remote Pairing plist schemas are recognized; key relationships and device compatibility remain unverified. Replacing stored credentials requires owner approval.")
                    }
                    Section("Existing local identities · read-only") {
                        Button("Inspect accessible Keychain identities") { model.inspectLocalIdentities() }.disabled(model.busy)
                        Text(model.identityStatus)
                        ForEach(model.identities) { identity in
                            VStack(alignment: .leading) {
                                Text("Subject OU (unverified): " + identity.metadata.subjectOrganizationalUnits.joined(separator: ", "))
                                Text("Certificate: " + identity.metadata.validity().rawValue).font(.caption)
                                if let trust = identity.offlineTrust {
                                    Text("Offline Apple PKI: " + (trust.blocker?.rawValue ?? "candidate only; revocation/profile/device status unverified")).font(.caption)
                                }
                                Button("Prove matching private-key access") { model.proveIdentity(identity) }
                                Text(model.identityProofs[identity.id] ?? "Not checked; iOS may request authorization for explicit private-key use").font(.caption)
                            }
                        }
                        Text("Discovery and a local challenge never revoke certificates, contact Apple or authorize installation.").font(.caption)
                    }
                    Section("Provisioning and transport") {
                        Button("Import provisioning profile for inspection") { select("profile") }.disabled(model.busy)
                        Text(model.profile)
                        Text("CMS trust validation, profile acquisition, VPN probes and authorized device-service connections remain unavailable.")
                    }
                }.navigationTitle("Signing Center")
            }.tabItem { Label("Signing", systemImage: "checkmark.seal") }
            NavigationStack {
                List {
                    Text("Inspection history persists locally, including interrupted operations. Exported history excludes source URLs, app identifiers and secrets. Other errors remain in memory.")
                    Button("Prepare redacted history export") { Task { await model.prepareDiagnosticExport() } }
                    if let file = model.diagnosticExport { ShareLink("Share redacted history", item: file) }
                    Section("Inspection operation history") {
                        ForEach(model.operations) { operation in
                            VStack(alignment: .leading) {
                                Text("\(operation.kind.rawValue) · \(operation.stage.rawValue)").font(.headline)
                                if operation.result == .running {
                                    TimelineView(.periodic(from: .now, by: 1)) { context in
                                        Text("Attempt \(operation.attempt) · \(Int(operation.elapsed(at: context.date))) seconds").font(.caption)
                                    }
                                } else {
                                    Text("Attempt \(operation.attempt) · \(Int(operation.elapsed())) seconds").font(.caption)
                                }
                                if let previous = operation.interruptedStage { Text("Interrupted during \(previous.rawValue); automatic resume disabled").font(.caption) }
                                if let diagnostic = operation.diagnostic {
                                    Text(diagnostic.category.rawValue).font(.caption)
                                    if let reason = diagnostic.reason { Text(reason.rawValue).font(.caption.monospaced()) }
                                    if let code = diagnostic.code { Text("Code \(code)").font(.caption.monospaced()) }
                                    if let status = diagnostic.httpStatus { Text("HTTP \(status)").font(.caption.monospaced()) }
                                }
                            }
                        }
                    }
                    ForEach(DiagnosticCategory.allCases, id: \.self) { Text($0.rawValue.capitalized) }
                    ForEach(model.diagnostics) { event in
                        VStack(alignment: .leading) { Text(event.category.rawValue); Text(event.message).font(.caption); if let reason = event.reason { Text(reason.rawValue).font(.caption.monospaced()) }; Text(event.date, style: .time) }
                    }
                }.navigationTitle("Diagnostics")
            }.tabItem { Label("Diagnostics", systemImage: "waveform.path.ecg") }
        }
        .scrollContentBackground(.hidden)
        .background(Color.black)
        .fileImporter(isPresented: $importer, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first { Task { await model.importFile(url, kind: kind) } }
        }
        .alert("Replace stored pairing credentials?", isPresented: $model.pairingReplacementPending) {
            Button("Replace after inspection") { model.approvePairingReplacement() }
            Button("Keep previous credentials", role: .cancel) { model.cancelPairingReplacement() }
        } message: {
            Text("The selected schema was inspected; device compatibility is unverified. Replacing existing pairing credentials may prevent future connections. Review this change before proceeding.")
        }
        .alert("Download untrusted IPA", isPresented: $downloadPrompt) {
            TextField("https://…", text: $downloadURL).textInputAutocapitalization(.never).autocorrectionDisabled()
            Button("Download and inspect") { Task { await model.download(downloadURL) } }
            Button("Cancel", role: .cancel) {}
        } message: { Text("Only download files you are authorized to use. HTTPS does not establish publisher authenticity. Redirects are rejected.") }
    }
    @ViewBuilder var appRows: some View {
        ForEach(model.items) { item in
            NavigationLink { InspectionView(item: item) } label: {
                Label { VStack(alignment: .leading) { Text(item.main.name); Text("\(item.main.version) · \(item.main.identifier)").font(.caption).foregroundStyle(.secondary) } } icon: { Image(systemName: "app.dashed") }
            }
        }
    }
}
struct InspectionView: View {
    let item: Inspection
    var body: some View {
        List {
            Section("Archive inspection") {
                LabeledContent("Version", value: item.main.version)
                LabeledContent("Build", value: item.main.build)
                LabeledContent("Bundle ID", value: item.main.identifier)
                LabeledContent("Team / expiration", value: "Unverified")
                LabeledContent("Available update", value: "Unknown")
                LabeledContent("Last completed operation", value: "Archive inspection")
                Text(item.importedAt, style: .date)
                Text("\(item.entries) archive entries · \(item.expandedBytes) expanded bytes")
            }
            Section("Unverified native-image metadata") {
                ForEach(item.nativeImages, id: \.path) { image in
                    VStack(alignment: .leading) {
                        Text(image.path).font(.caption.monospaced())
                        Text(image.info.slices.map(\.architecture).joined(separator: ", ")).font(.caption)
                        Text(image.info.encrypted ? "Encrypted code detected; signing blocked" : "No encrypted range declared; not proof of compatibility").font(.caption)
                        Text(image.info.signatureEnvelopePresent ? "Signature envelope present; validity unverified" : "No signature envelope in all slices").font(.caption)
                        ForEach(Array(image.info.slices.enumerated()), id: \.offset) { _, slice in
                            if let entitlements = slice.xmlEntitlements { Text("Untrusted XML entitlement keys: " + entitlements.keys.sorted().joined(separator: ", ")).font(.caption) }
                            if slice.derEntitlementsPresent { Text("DER entitlements present; semantics unverified").font(.caption) }
                        }
                    }
                }
            }
            Section("Signing targets · children first") { ForEach(item.signingOrder, id: \.self) { Text($0).font(.caption.monospaced()) } }
            Section("Findings") { ForEach(item.warnings, id: \.self) { Text($0) } }
            Section("Device operations") {
                ForEach(["Install", "Update", "Refresh"], id: \.self) { title in Button(title) {}.disabled(true) }
                Text("Kodi and KappaForge are never deleted. Data preservation has not been demonstrated.")
            }
        }.navigationTitle(item.main.name)
    }
}
