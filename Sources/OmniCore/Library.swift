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
        let records = try JSONDecoder().decode([Inspection].self, from: BoundedFile.read(url, maximumBytes: 16_777_216))
        guard records.count <= 4096, Set(records.map(\.id)).count == records.count else { throw OmniError.corruptedState }
        for record in records {
            let values = try directory.appendingPathComponent(record.id.uuidString + ".ipa").resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else { throw OmniError.corruptedState }
        }
        return records
    }
    public func importIPA(_ source: URL) throws -> Inspection {
        let inspector = IPAInspector()
        let staging = directory.appendingPathComponent(UUID().uuidString + ".part")
        defer { try? FileManager.default.removeItem(at: staging) }
        guard (try source.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max) <= inspector.maximumArchiveBytes else { throw OmniError.limitsExceeded }
        try BoundedFile.copy(source, to: staging, maximumBytes: inspector.maximumArchiveBytes)
        let result = try inspector.inspect(staging)
        let destination = directory.appendingPathComponent(result.id.uuidString + ".ipa")
        try FileManager.default.moveItem(at: staging, to: destination)
        do {
            var items = try load()
            guard items.count < 4096 else { throw OmniError.limitsExceeded }
            items.append(result)
            let encoded = try JSONEncoder().encode(items)
            guard encoded.count <= 16_777_216 else { throw OmniError.limitsExceeded }
            try encoded.write(to: directory.appendingPathComponent("index.json"), options: .atomic)
        } catch {
            try? FileManager.default.removeItem(at: destination); throw error
        }
        return result
    }
}
