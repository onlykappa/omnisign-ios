import Foundation

/// Reads a bounded DER CMS eContent payload. It deliberately grants no CMS/Apple trust.
public struct ProfileEnvelope: Sendable {
    public let summary: ProfileSummary
    public let signerCount: Int
    public let profileName: String?
    public var cmsSignatureVerified: Bool { false }
    public init(cms: Data, now: Date = Date()) throws {
        guard cms.count <= 2_097_152 else { throw OmniError.limitsExceeded }
        do {
            let bytes = Array(cms)
            let outer = try DERNode.read(bytes, at:0, limit:bytes.count)
            guard outer.tag == 0x30, outer.end == bytes.count else { throw OmniError.invalidProfile }
            let content = try outer.children(bytes)
            let signedDataOID: [UInt8] = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02]
            let dataOID: [UInt8] = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01]
            guard content.count == 2, content[0].tag == 0x06,
                  Array(bytes[content[0].body..<content[0].end]) == signedDataOID, content[1].tag == 0xA0 else { throw OmniError.invalidProfile }
            let wrapped = try content[1].children(bytes)
            guard wrapped.count == 1, wrapped[0].tag == 0x30 else { throw OmniError.invalidProfile }
            let signed = try wrapped[0].children(bytes)
            guard signed.count >= 4, signed.count <= 6, signed[0].tag == 0x02, signed[1].tag == 0x31,
                  signed[2].tag == 0x30, let last = signed.last, last.tag == 0x31 else { throw OmniError.invalidProfile }
            let signers = try last.children(bytes)
            guard !signers.isEmpty, signers.count <= 32, signers.allSatisfy({ $0.tag == 0x30 }) else { throw OmniError.invalidProfile }
            signerCount = signers.count
            let payload = try signed[2].children(bytes)
            guard payload.count == 2, payload[0].tag == 0x06, Array(bytes[payload[0].body..<payload[0].end]) == dataOID,
                  payload[1].tag == 0xA0 else { throw OmniError.invalidProfile }
            let value = try payload[1].children(bytes)
            guard value.count == 1, value[0].tag == 0x04, value[0].end - value[0].body <= 1_048_576 else { throw OmniError.invalidProfile }
            let plist = Data(bytes[value[0].body..<value[0].end])
            summary = try ProfileSummary(decodedPlist:plist, now:now, allowExpiredForInspection:true)
            let object = try PropertyListSerialization.propertyList(from:plist,format:nil) as? [String:Any]
            let name = object?["Name"] as? String
            guard name == nil || (name!.utf8.count <= 255 && !name!.unicodeScalars.contains(where: { $0.value < 32 })) else { throw OmniError.invalidProfile }
            profileName = name
        } catch OmniError.limitsExceeded { throw OmniError.limitsExceeded }
        catch { throw OmniError.invalidProfile }
    }
    public func requireTrustedForSigning() throws -> Never { throw OmniError.unavailable }
}
