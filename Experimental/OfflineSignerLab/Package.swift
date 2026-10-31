// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "OmniSigningLab",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .executable(name: "omnisign-lab", targets: ["OmniSigningLab"]),
        .library(name: "IndependentCMSVerifier", targets: ["IndependentCMSVerifier"]),
        .library(name: "DisposableSigningSupport", targets: ["DisposableSigningSupport"])
    ],
    dependencies: [
        .package(path: "../Vendor/CodeSignKit"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.3.1")
    ],
    targets: [
        .target(name: "DisposableSigningSupport", dependencies: [
            .product(name: "CodeSignKit", package: "CodeSignKit"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "CryptoExtras", package: "swift-crypto")
        ]),
        .target(name: "IndependentCMSVerifier", dependencies: [
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "CryptoExtras", package: "swift-crypto")
        ]),
        .executableTarget(name: "OmniSigningLab", dependencies: [
            "DisposableSigningSupport", "IndependentCMSVerifier",
            .product(name: "CodeSignKit", package: "CodeSignKit")
        ]),
        .testTarget(name: "CMSVerifierTests", dependencies: [
            "DisposableSigningSupport", "IndependentCMSVerifier",
            .product(name: "CodeSignKit", package: "CodeSignKit")
        ], path: "Tests", resources: [.copy("Fixtures")])
    ],
    swiftLanguageModes: [.v5]
)
