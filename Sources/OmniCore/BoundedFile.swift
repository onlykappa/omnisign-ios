import Foundation

/// Actual bytes, rather than a racy pre-copy stat, enforce every bound.
public enum BoundedFile {
    public static func read(_ source: URL, maximumBytes: Int) throws -> Data {
        guard maximumBytes >= 0 else { throw OmniError.limitsExceeded }
        let handle = try FileHandle(forReadingFrom: source)
        defer { try? handle.close() }
        var result = Data()
        while let chunk = try handle.read(upToCount: 65_536), !chunk.isEmpty {
            guard chunk.count <= maximumBytes - result.count else { throw OmniError.limitsExceeded }
            result.append(chunk)
        }
        return result
    }
    @discardableResult public static func copy(_ source: URL, to destination: URL, maximumBytes: Int64) throws -> Int64 {
        guard maximumBytes >= 0, !FileManager.default.fileExists(atPath: destination.path) else { throw OmniError.limitsExceeded }
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        guard FileManager.default.createFile(atPath: destination.path, contents: nil) else { throw OmniError.unavailable }
        var committed = false
        defer { if !committed { try? FileManager.default.removeItem(at: destination) } }
        let output = try FileHandle(forWritingTo: destination)
        defer { try? output.close() }
        var total: Int64 = 0
        while let chunk = try input.read(upToCount: 65_536), !chunk.isEmpty {
            guard Int64(chunk.count) <= maximumBytes - total else { throw OmniError.limitsExceeded }
            try output.write(contentsOf: chunk)
            total += Int64(chunk.count)
        }
        try output.synchronize()
        committed = true
        return total
    }
}
public enum IdentifierRules {
    public static func bundle(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 255 else { return false }
        return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { part in
            !part.isEmpty && part.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }
        }
    }
}
