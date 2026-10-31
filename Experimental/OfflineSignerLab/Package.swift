// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "OmniSigningLab", platforms: [.macOS(.v13), .iOS(.v17)], products: [.executable(name: "omnisign-lab", targets: ["OmniSigningLab"])], dependencies: [.package(url: "https://github.com/mahee96/CodeSignKit.git", revision: "d0c67710fda9a2646b9e829cb2cf443892728371")], targets: [.executableTarget(name: "OmniSigningLab", dependencies: [.product(name: "CodeSignKit", package: "CodeSignKit")])], swiftLanguageModes: [.v5])
