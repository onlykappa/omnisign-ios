import Foundation
import ZIPFoundation

public enum OmniError: String, Error, LocalizedError, Codable {
    case unsafeArchive, limitsExceeded, malformedBundle, unsupportedExecutable, unavailable, incompatible, invalidProfile, invalidCertificate, certificateExpired, certificateNotYetValid, privateKeyUnavailable, unsupportedKeyAlgorithm, keyOperationDenied, invalidPairing, ambiguousPairing, corruptedState, invalidTransition, interrupted
    public var errorDescription: String? { rawValue }
}
public struct BundleRecord: Codable, Equatable, Sendable {
    public let path: String
    public let identifier: String
    public let name: String
    public let version: String
    public let build: String
    public let executable: String
}
public struct Inspection: Codable, Identifiable, Sendable {
    public let id: UUID
    public let importedAt: Date
    public let bundles: [BundleRecord]
    public let nativeLibraries: [String]
    public let nativeImages: [NativeImageRecord]
    public let entries: Int
    public let expandedBytes: Int64
    public let warnings: [String]
    public var main: BundleRecord { bundles[0] }
    private enum CodingKeys: String, CodingKey { case id, importedAt, bundles, nativeLibraries, nativeImages, entries, expandedBytes, warnings }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id); importedAt = try c.decode(Date.self, forKey: .importedAt)
        bundles = try c.decode([BundleRecord].self, forKey: .bundles)
        nativeLibraries = try c.decode([String].self, forKey: .nativeLibraries)
        nativeImages = try c.decodeIfPresent([NativeImageRecord].self, forKey: .nativeImages) ?? []
        entries = try c.decode(Int.self, forKey: .entries); expandedBytes = try c.decode(Int64.self, forKey: .expandedBytes)
        warnings = try c.decode([String].self, forKey: .warnings)
        try validate()
    }
    init(id: UUID, importedAt: Date, bundles: [BundleRecord], nativeLibraries: [String], entries: Int, expandedBytes: Int64, warnings: [String], nativeImages: [NativeImageRecord] = []) {
        self.id = id; self.importedAt = importedAt; self.bundles = bundles; self.nativeLibraries = nativeLibraries
        self.entries = entries; self.expandedBytes = expandedBytes; self.warnings = warnings; self.nativeImages = nativeImages
    }
    public func validate() throws {
        guard let root = bundles.first, !bundles.isEmpty, bundles.count <= 1024, importedAt >= Date(timeIntervalSince1970: 0), importedAt <= Date.distantFuture,
              root.path.hasPrefix("Payload/"), root.path.hasSuffix(".app"), root.path.split(separator: "/").count == 2,
              entries > 0, entries <= 30_000, expandedBytes >= 0, expandedBytes <= 2_147_483_648,
              nativeImages.count <= 1024, warnings.count <= 100, warnings.allSatisfy({ $0.utf8.count <= 4096 }), nativeLibraries.count <= 10_000,
              Set(bundles.map(\.path)).count == bundles.count else { throw OmniError.corruptedState }
        for bundle in bundles {
            try IPAInspector.validatePath(bundle.path)
            guard bundle.path == root.path || bundle.path.hasPrefix(root.path + "/"), IdentifierRules.bundle(bundle.identifier),
                  !bundle.executable.isEmpty, !bundle.executable.contains("/"), !bundle.executable.contains("\\"),
                  bundle.executable != ".", bundle.executable != "..", bundle.executable.utf8.count <= 255,
                  bundle.name.utf8.count <= 4096, bundle.version.utf8.count <= 128, bundle.build.utf8.count <= 128 else { throw OmniError.corruptedState }
        }
        for path in nativeLibraries {
            try IPAInspector.validatePath(path)
            guard path.hasPrefix(root.path + "/") else { throw OmniError.corruptedState }
        }
        for image in nativeImages {
            try IPAInspector.validatePath(image.path)
            guard image.path.hasPrefix(root.path + "/"), !image.info.slices.isEmpty, image.info.slices.count <= 32 else { throw OmniError.corruptedState }
            for slice in image.info.slices {
                guard slice.offset >= 0, slice.size >= 28, slice.offset <= 536_870_912 - slice.size else { throw OmniError.corruptedState }
            }
        }
    }
    public var signingOrder: [String] {
        Array(Set(nativeLibraries + bundles.map(\.path))).sorted {
            let a = $0.split(separator: "/").count, b = $1.split(separator: "/").count
            return a == b ? $0 < $1 : a > b
        }
    }
}
public struct IPAInspector: Sendable {
    public let maximumArchiveBytes: Int64 = 1_073_741_824
    public let maximumExpandedBytes: Int64 = 2_147_483_648
    public init() {}
    public static func validatePath(_ path: String) throws {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !path.isEmpty, path.utf8.count <= 4096, parts.count <= 128, !path.hasPrefix("/"), !path.contains("\\"), !path.contains(":"),
              !path.unicodeScalars.contains(where: { $0.value < 32 }),
              !parts.contains(".."), !parts.contains("."),
              !parts.dropLast().contains("") else { throw OmniError.unsafeArchive }
    }
    public func inspect(_ url: URL) throws -> Inspection {
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max
        guard size <= maximumArchiveBytes else { throw OmniError.limitsExceeded }
        let archive = try Archive(url: url, accessMode: .read)
        var paths = Set<String>(), records: [String: Data] = [:], allPaths = Set<String>()
        var total: Int64 = 0, count = 0, retained = 0
        for entry in archive {
            try Self.validatePath(entry.path)
            count += 1
            guard count <= 30_000, entry.type != .symlink,
                  paths.insert(entry.path.precomposedStringWithCanonicalMapping.lowercased()).inserted else { throw OmniError.unsafeArchive }
            guard entry.uncompressedSize <= 536_870_912 else { throw OmniError.limitsExceeded }
            let expanded = Int64(entry.uncompressedSize)
            guard expanded <= 536_870_912, total <= maximumExpandedBytes - expanded else { throw OmniError.limitsExceeded }
            total += expanded
            allPaths.insert(entry.path)
            // Stream every entry to verify its CRC; retain only bounded metadata and executable headers.
            var prefix = Data(), actual: Int64 = 0
            let cap = entry.path.hasSuffix("/Info.plist") ? 1_048_576 : 4096
            let checksum = try archive.extract(entry, skipCRC32: false) { chunk in
                actual += Int64(chunk.count)
                guard actual <= expanded else { throw OmniError.limitsExceeded }
                if prefix.count < cap { prefix.append(chunk.prefix(cap - prefix.count)) }
            }
            guard actual == expanded, checksum == entry.checksum else { throw OmniError.unsafeArchive }
            if entry.path.hasSuffix("/Info.plist"), actual > cap { throw OmniError.limitsExceeded }
            retained += prefix.count
            guard retained <= 67_108_864 else { throw OmniError.limitsExceeded }
            records[entry.path] = prefix
        }
        let roots = Set(allPaths.compactMap { path -> String? in
            let parts = path.split(separator: "/")
            return parts.count >= 2 && parts[0] == "Payload" && parts[1].hasSuffix(".app") ? "Payload/\(parts[1])" : nil
        })
        guard roots.count == 1, let root = roots.first else { throw OmniError.malformedBundle }
        let bundlePaths = Set(allPaths.filter { $0.hasSuffix("/Info.plist") }.map { String($0.dropLast(11)) }.filter {
            $0 == root || ($0.hasPrefix(root + "/") && ($0.hasSuffix(".appex") || $0.hasSuffix(".framework") || $0.hasSuffix(".app")))
        })
        // Every recognized nested code bundle must have metadata; do not silently omit malformed frameworks.
        for entryPath in allPaths where entryPath.hasPrefix(root + "/") {
            let components = entryPath.split(separator: "/")
            for index in components.indices where components[index].hasSuffix(".framework") || components[index].hasSuffix(".appex") || components[index].hasSuffix(".app") {
                let bundlePath = components[...index].joined(separator: "/")
                guard bundlePaths.contains(bundlePath) else { throw OmniError.malformedBundle }
            }
        }
        var bundles: [BundleRecord] = []
        for path in bundlePaths {
            guard let data = records[path + "/Info.plist"],
                  let info = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let identifier = info["CFBundleIdentifier"] as? String, !identifier.isEmpty,
                  let executable = info["CFBundleExecutable"] as? String, !executable.isEmpty,
                  !executable.contains("/"), executable != ".", executable != "..",
                  let header = records[path + "/" + executable] else { throw OmniError.malformedBundle }
            try Self.checkMachO(header)
            bundles.append(BundleRecord(path: path, identifier: identifier, name: info["CFBundleDisplayName"] as? String ?? info["CFBundleName"] as? String ?? identifier, version: info["CFBundleShortVersionString"] as? String ?? "Unknown", build: info["CFBundleVersion"] as? String ?? "Unknown", executable: executable))
        }
        guard bundles.contains(where: { $0.path == root }) else { throw OmniError.malformedBundle }
        let executablePaths = Set(bundles.map { $0.path + "/" + $0.executable })
        let libraries = allPaths.filter { path in
            guard path.hasPrefix(root + "/"), !executablePaths.contains(path), !path.hasSuffix("/") else { return false }
            let prefix = records[path] ?? Data()
            let magic = Array(prefix.prefix(4))
            let thinMagics: [[UInt8]] = [[0xCF,0xFA,0xED,0xFE],[0xFE,0xED,0xFA,0xCF],[0xCE,0xFA,0xED,0xFE],[0xFE,0xED,0xFA,0xCE]]
            return path.hasSuffix(".dylib") || path.hasSuffix(".so") || thinMagics.contains(magic)
        }.sorted()
        for library in libraries { try Self.checkMachO(records[library] ?? Data()) }
        let codePaths = Array(executablePaths.union(libraries)).sorted()
        guard codePaths.count <= 1024 else { throw OmniError.limitsExceeded }
        var images: [NativeImageRecord] = [], metadataBytes = 0, streamed: Int64 = 0
        for path in codePaths {
            guard let entry = archive[path], entry.type == .file else { throw OmniError.malformedBundle }
            let info = try NativeBinaryInspector.inspect(size: Int(entry.uncompressedSize)) { range in
                var output = Data(), position = 0
                do {
                    _ = try archive.extract(entry, skipCRC32: true) { chunk in
                        streamed += Int64(chunk.count)
                        guard streamed <= 4_294_967_296 else { throw OmniError.limitsExceeded }
                        let lower = max(position, range.lowerBound), upper = min(position + chunk.count, range.upperBound)
                        if lower < upper { output.append(chunk.subdata(in: (lower - position)..<(upper - position))) }
                        position += chunk.count
                        if position >= range.upperBound { throw RangeExtractionComplete.done }
                    }
                } catch RangeExtractionComplete.done { /* CRC was verified in the full initial archive pass. */ }
                guard output.count == range.count else { throw OmniError.unsupportedExecutable }
                return output
            }
            let image = NativeImageRecord(path: path, info: info)
            metadataBytes += try JSONEncoder().encode(image).count
            guard metadataBytes <= 8_388_608 else { throw OmniError.limitsExceeded }
            images.append(image)
        }
        bundles.sort { if $0.path == root { return true }; if $1.path == root { return false }; return $0.path < $1.path }
        let result = Inspection(id: UUID(), importedAt: Date(), bundles: bundles, nativeLibraries: libraries, entries: count, expandedBytes: total, warnings: ["CRC verifies archive integrity, not publisher authenticity.", "Mach-O architecture, load-command bounds, encryption flags and signature envelopes inspected. XML entitlements are untrusted; CMS, code/resource hashes, DER entitlement semantics, loadability and device compatibility remain unverified.", "Signing and installation are disabled pending audited backends and real-device acceptance."], nativeImages: images)
        try result.validate()
        return result
    }
    public static func checkMachO(_ data: Data) throws {
        let magics: [[UInt8]] = [[0xce,0xfa,0xed,0xfe],[0xfe,0xed,0xfa,0xce],[0xcf,0xfa,0xed,0xfe],[0xfe,0xed,0xfa,0xcf],[0xca,0xfe,0xba,0xbe],[0xbe,0xba,0xfe,0xca],[0xca,0xfe,0xba,0xbf],[0xbf,0xba,0xfe,0xca]]
        guard data.count >= 32, magics.contains(Array(data.prefix(4))) else { throw OmniError.unsupportedExecutable }
    }
}

private enum RangeExtractionComplete: Error { case done }
