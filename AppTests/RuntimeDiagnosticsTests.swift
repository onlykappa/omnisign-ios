import XCTest
@testable import OmniSign

final class RuntimeDiagnosticsTests: XCTestCase {
    @MainActor func testRuntimeExportHasOnlyWhitelistedNonPersonalContext() throws {
        let runtime = RuntimeDiagnosticContext.capture()
        XCTAssertFalse(runtime.osVersion.isEmpty); XCTAssertFalse(runtime.hardwareModel.isEmpty)
        #if targetEnvironment(simulator)
        XCTAssertEqual(runtime.kind,.iOSSimulator)
        #else
        XCTAssertEqual(runtime.kind,.iOSDevice)
        #endif
        let data = try JSONEncoder().encode(runtime)
        let object = try JSONSerialization.jsonObject(with:data) as! [String:Any]
        XCTAssertEqual(Set(object.keys),Set(["kind","osVersion","hardwareModel","buildSDK","appVersion","appBuild"]))
        for excluded in ["deviceName","UDID","serial","SSID","MACAddress","AppleID","teamIdentifier"] { XCTAssertNil(object[excluded]) }
    }
    @MainActor func testAvailableNetworkAndTunnelHintsDoNotBecomeTransportProof() throws {
        let network = PassiveNetworkSnapshot(path:.available,tunnelInterfaceCount:3)
        XCTAssertEqual(network.transport,.notProbed)
        let export = DiagnosticExportEnvelope(runtime:.capture(),network:network,operations:[])
        let object = try JSONSerialization.jsonObject(with:JSONEncoder().encode(export)) as! [String:Any]
        let fields = object["network"] as! [String:Any]
        XCTAssertEqual(Set(fields.keys),Set(["path","tunnelInterfaceCount","transport"]))
        XCTAssertEqual(fields["transport"] as? String,"notProbed")
    }
}
