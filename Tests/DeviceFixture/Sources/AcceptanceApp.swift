// SPDX-License-Identifier: MIT
import SwiftUI

/// Disposable acceptance fixture. Contains no signing, transport, account or owner-app APIs.
@main
struct AcceptanceApp: App {
    var body: some Scene { WindowGroup { AcceptanceView() } }
}

struct AcceptanceView: View {
    @AppStorage("acceptance.savedValue") private var savedValue = ""
    @AppStorage("acceptance.saveCount") private var saveCount = 0
    @State private var draft = ""
    private var version: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Unknown" }
    private var build: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "Unknown" }
    var body: some View {
        NavigationStack {
            Form {
                Section("Disposable test application") {
                    Text("Version \(version) · build \(build)").accessibilityIdentifier("fixture.version")
                    Text("Use a non-sensitive test value to check whether this app retains data after refresh or an in-place update. This screen does not verify signing or installation.")
                }
                Section("Saved locally") {
                    Text(savedValue.isEmpty ? "No value saved" : savedValue)
                        .accessibilityIdentifier("fixture.savedValue")
                    LabeledContent("Times saved", value: String(saveCount))
                }
                Section("Record a test value") {
                    TextField("Example: violet-test-42", text: $draft)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .accessibilityIdentifier("fixture.input")
                    Button("Save test value") {
                        savedValue = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                        saveCount += 1
                        draft = ""
                    }
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || draft.utf8.count > 128)
                    .accessibilityIdentifier("fixture.save")
                }
                Section("Acceptance procedure") {
                    Text("Save → close and reopen → refresh → reopen → update to version 1.1 → reopen. Record each actual result separately. A displayed value does not prove which signing or installation tool performed the update.")
                    Text("Do not uninstall between versions. Uninstalling may erase this app’s saved value. Never replace Kodi or KappaForge with this fixture.")
                }
            }.navigationTitle("OmniSign Test")
        }
    }
}
