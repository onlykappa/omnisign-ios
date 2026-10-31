// swift-tools-version: 6.0
// SPDX-License-Identifier: AGPL-3.0-only
import PackageDescription
let package = Package(name:"CodeSignKit", platforms:[.iOS(.v17),.macOS(.v13)], products:[.library(name:"CodeSignKit",targets:["CodeSignKit"])], dependencies:[.package(url:"https://github.com/apple/swift-crypto.git",exact:"4.3.1"),.package(url:"https://github.com/apple/swift-asn1.git",exact:"1.6.0")], targets:[.target(name:"CodeSignKit",dependencies:[.product(name:"Crypto",package:"swift-crypto"),.product(name:"CryptoExtras",package:"swift-crypto"),.product(name:"SwiftASN1",package:"swift-asn1")],path:"Sources")], swiftLanguageModes:[.v5])
