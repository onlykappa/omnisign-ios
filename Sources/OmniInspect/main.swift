import Foundation
import OmniCore
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif
// Explicit inspection output contains application metadata. Do not treat it as redacted diagnostics.
guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("Usage: omnisign-inspect <file.ipa>\n".utf8)); exit(2)
}
do {
    let result = try IPAInspector().inspect(URL(fileURLWithPath: CommandLine.arguments[1]))
    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
    FileHandle.standardOutput.write(try encoder.encode(result)); print()
} catch {
    let reason = (error as? OmniError)?.rawValue ?? "archiveReadFailed"
    FileHandle.standardError.write(Data("Inspection rejected: \(reason)\n".utf8)); exit(1)
}
