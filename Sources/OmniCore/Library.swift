import Foundation
public struct Library: Sendable {
    public let directory: URL
    public init(directory: URL) throws {
        self.directory = directory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }
    public func load() throws -> [Inspection] {
        let url = directory.appendingPathComponent("index.json")
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        return try JSONDecoder().decode([Inspection].self, from: Data(contentsOf: url))
    }
    public func importIPA(_ source: URL) throws -> Inspection {
        let inspector = IPAInspector()
        let staging = directory.appendingPathComponent(UUID().uuidString + ".part")
        defer { try? FileManager.default.removeItem(at: staging) }
        guard (try source.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max) <= inspector.maximumArchiveBytes else { throw OmniError.limitsExceeded }
        try FileManager.default.copyItem(at: source, to: staging)
        let result = try inspector.inspect(staging)
        let destination = directory.appendingPathComponent(result.id.uuidString + ".ipa")
        try FileManager.default.moveItem(at: staging, to: destination)
        do {
            var items = try load(); items.append(result)
            try JSONEncoder().encode(items).write(to: directory.appendingPathComponent("index.json"), options: .atomic)
        } catch {
            try? FileManager.default.removeItem(at: destination); throw error
        }
        return result
    }
}
