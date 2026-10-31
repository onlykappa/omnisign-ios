import Foundation
import UIKit
import SwiftUI
import UniformTypeIdentifiers
import OmniCore

@MainActor final class AppModel: ObservableObject {
    @Published var items: [Inspection] = []
    @Published var diagnostics: [Diagnostic] = []
    @Published var busy = false
    @Published var status = "Ready to inspect"
    @Published var pairing = "Not imported"
    @Published var certificate = "Not inspected"
    private(set) var library: Library?
    init() {
        do {
            let directory = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("Library", isDirectory: true)
            library = try Library(directory: directory)
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: directory.path)
            var values = URLResourceValues(); values.isExcludedFromBackup = true
            var protectedURL = directory; try protectedURL.setResourceValues(values)
            items = try library!.load()
            if SecureStore().contains("pairing") { pairing = "Stored; connection unverified" }
        } catch { library = nil; status = "Library unavailable; imports disabled" }
    }
    func record(_ category: DiagnosticCategory, error: Error? = nil) {
        diagnostics.append(Diagnostic(category: category, code: (error as? SecureStoreError).map { Int($0.code) }, reason: error as? OmniError)); status = "Operation stopped; see Diagnostics"
    }
    func importFile(_ url: URL, kind: String) async {
        guard !busy else { return }; busy = true; status = "Inspecting…"
        defer { busy = false }
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        do {
            if kind == "ipa" {
                guard let library else { throw OmniError.unavailable }
                let result = try await Task.detached { try library.importIPA(url) }.value
                items.append(result); status = "Imported and inspected; signing unverified"
            } else {
                guard (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max) <= 2_097_152 else { throw OmniError.limitsExceeded }
                let data = try Data(contentsOf: url)
                if kind == "pairing" {
                    try PairingInspector.validate(data); try SecureStore().save(data, key: "pairing")
                    pairing = "Stored; connection unverified"; status = "Pairing schema inspected"
                } else {
                    certificate = try SecureStore().inspectCertificate(data)
                    try SecureStore().save(data, key: "certificate"); status = "Certificate inspected"
                }
            }
        } catch { record(kind == "pairing" ? .pairing : kind == "certificate" ? .certificate : .inspection, error: error) }
    }
    func download(_ string: String) async {
        guard !busy, let url = URL(string: string), url.scheme == "https", url.user == nil, url.password == nil, url.host != nil else { record(.transport); return }
        busy = true; status = "Downloading untrusted source…"
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { busy = false; try? FileManager.default.removeItem(at: temporary) }
        do {
            // Ephemeral session avoids persistent cookies and cached authentication.
            let config = URLSessionConfiguration.ephemeral; config.timeoutIntervalForRequest = 30; config.timeoutIntervalForResource = 180
            let session = URLSession(configuration: config, delegate: NoRedirect(), delegateQueue: nil)
            defer { session.invalidateAndCancel() }
            let (bytes, response) = try await session.bytes(from: url)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200, response.expectedContentLength <= 1_073_741_824 else { throw OmniError.unavailable }
            FileManager.default.createFile(atPath: temporary.path, contents: nil)
            let handle = try FileHandle(forWritingTo: temporary); defer { try? handle.close() }
            var count = 0, buffer = Data()
            for try await byte in bytes {
                count += 1; guard count <= 1_073_741_824 else { throw OmniError.limitsExceeded }
                buffer.append(byte)
                if buffer.count >= 65_536 { try handle.write(contentsOf: buffer); buffer.removeAll(keepingCapacity: true) }
            }
            try handle.write(contentsOf: buffer); try handle.close()
            guard let library else { throw OmniError.unavailable }
            let result = try await Task.detached { try library.importIPA(temporary) }.value
            items.append(result); status = "Downloaded and inspected; source authenticity unverified"
        } catch { record(.transport, error: error) }
    }
}
final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
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
    private func select(_ value: String) { kind = value; importer = true }
    var body: some View {
        TabView {
            NavigationStack {
                List {
                    Section {
                        Label("OmniSign · Experimental", systemImage: "signature").font(.title2.bold())
                        Text("Signing and device services are disabled pending validation.").foregroundStyle(.secondary)
                        Button { select("ipa") } label: { Label("Import IPA", systemImage: "plus.app.fill") }.buttonStyle(.borderedProminent)
                        Text(model.status)
                        if model.busy { ProgressView() }
                    }
                    Section("This iPhone") {
                        LabeledContent("Device", value: UIDevice.current.model)
                        LabeledContent("OS", value: UIDevice.current.systemVersion)
                        LabeledContent("Signing", value: "Unavailable")
                        LabeledContent("Certificate expiry", value: "Unknown")
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
                    Button("Import from Files") { select("ipa") }
                    Button("Download from HTTPS URL…") { downloadPrompt = true }
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
                        Button("Import DER certificate") { select("certificate") }
                        Text(model.certificate)
                        Text("Certificate expiration and development eligibility require a complete certificate backend.")
                        Button("Import legacy pairing plist") { select("pairing") }
                        Text(model.pairing)
                        Text("Pairing secrets are stored in this device’s Keychain. Import does not verify connection compatibility. Remote pairing formats are unsupported.")
                    }
                    Section("Provisioning and transport") {
                        Text("CMS trust validation, profile acquisition, VPN probes and authorized device-service connections remain unavailable.")
                    }
                }.navigationTitle("Signing Center")
            }.tabItem { Label("Signing", systemImage: "checkmark.seal") }
            NavigationStack {
                List {
                    Text("No raw backend errors or personal identifiers are logged. Diagnostics in this build remain in memory.")
                    ForEach(DiagnosticCategory.allCases, id: \.self) { Text($0.rawValue.capitalized) }
                    ForEach(model.diagnostics) { event in
                        VStack(alignment: .leading) { Text(event.category.rawValue); Text(event.message).font(.caption); if let reason = event.reason { Text(reason.rawValue).font(.caption.monospaced()) }; Text(event.date, style: .time) }
                    }
                }.navigationTitle("Diagnostics")
            }.tabItem { Label("Diagnostics", systemImage: "waveform.path.ecg") }
        }
        .scrollContentBackground(.hidden)
        .background(Color.black)
        .disabled(model.busy)
        .fileImporter(isPresented: $importer, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first { Task { await model.importFile(url, kind: kind) } }
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
            Section("Signing targets · children first") { ForEach(item.signingOrder, id: \.self) { Text($0).font(.caption.monospaced()) } }
            Section("Findings") { ForEach(item.warnings, id: \.self) { Text($0) } }
            Section("Device operations") {
                ForEach(["Install", "Update", "Refresh"], id: \.self) { title in Button(title) {}.disabled(true) }
                Text("Kodi and KappaForge are never deleted. Data preservation has not been demonstrated.")
            }
        }.navigationTitle(item.main.name)
    }
}
