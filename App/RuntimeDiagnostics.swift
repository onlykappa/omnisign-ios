import Foundation
import UIKit
import Network
import Darwin
import OmniCore

enum RuntimeKind: String, Codable, Sendable { case iOSDevice, iOSSimulator }
struct RuntimeDiagnosticContext: Encodable, Sendable {
    let kind: RuntimeKind
    let osVersion: String
    let hardwareModel: String
    let buildSDK: String
    let appVersion: String
    let appBuild: String
    @MainActor static func capture() -> Self {
        var info = utsname()
        let status = uname(&info)
        let capacity = MemoryLayout.size(ofValue:info.machine)
        let machine = withUnsafePointer(to:&info.machine) { pointer in
            pointer.withMemoryRebound(to:CChar.self,capacity:capacity) { String(cString:$0) }
        }
        #if targetEnvironment(simulator)
        let kind = RuntimeKind.iOSSimulator
        let model = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? machine
        #else
        let kind = RuntimeKind.iOSDevice
        let model = machine
        #endif
        func clean(_ value: String?) -> String {
            guard let value, !value.isEmpty, value.utf8.count <= 64,
                  value.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [44,45,46,95].contains($0) }) else { return "Unknown" }
            return value
        }
        let metadata = Bundle.main.infoDictionary ?? [:]
        return Self(kind:kind,osVersion:clean(UIDevice.current.systemVersion),hardwareModel:status == 0 ? clean(model) : "Unknown",
                    buildSDK:clean(metadata["DTSDKName"] as? String),appVersion:clean(metadata["CFBundleShortVersionString"] as? String),appBuild:clean(metadata["CFBundleVersion"] as? String))
    }
}
enum NetworkReachability: String, Codable, Sendable { case unknown, available, unavailable, requiresConnection }
enum DeviceTransportObservation: String, Codable, Sendable { case notProbed }
struct PassiveNetworkSnapshot: Encodable, Sendable {
    let path: NetworkReachability
    let tunnelInterfaceCount: Int?
    let transport: DeviceTransportObservation = .notProbed
    var transportSummary: String {
        "Not probed; " + (tunnelInterfaceCount.map { "\($0) tunnel interfaces observed" } ?? "interface observation unavailable")
    }
}
struct DiagnosticExportEnvelope: Encodable, Sendable {
    let schemaVersion = 2
    let runtime: RuntimeDiagnosticContext
    let network: PassiveNetworkSnapshot
    let operations: [WorkRecord]
}
/// Observes OS state only; never opens a device connection or infers VPN/pairing/install success.
final class PassiveNetworkObserver {
    private let monitor = NWPathMonitor()
    init(update: @escaping @Sendable (PassiveNetworkSnapshot) -> Void) {
        monitor.pathUpdateHandler = { path in
            let state: NetworkReachability
            switch path.status {
            case .satisfied: state = .available
            case .unsatisfied: state = .unavailable
            case .requiresConnection: state = .requiresConnection
            @unknown default: state = .unknown
            }
            update(PassiveNetworkSnapshot(path:state,tunnelInterfaceCount:Self.tunnelCount()))
        }
        monitor.start(queue:DispatchQueue(label:"org.omnisign.passive-network"))
    }
    deinit { monitor.cancel() }
    private static func tunnelCount() -> Int? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return nil }
        defer { freeifaddrs(head) }
        var node = head, count = 0
        var names = Set<String>()
        while let current = node {
            count += 1
            guard count <= 2048 else { return nil }
            if let name = current.pointee.ifa_name, current.pointee.ifa_flags & UInt32(IFF_UP) != 0 {
                let value = String(cString:name)
                if value.hasPrefix("utun") { names.insert(value) }
            }
            node = current.pointee.ifa_next
        }
        return names.count
    }
}
