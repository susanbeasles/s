#if os(macOS)
import Foundation
import Security

/// Verifies Mach-O bundles on the macOS host using `Security.framework` (`SecStaticCode`)
/// against Apple Root CA + pinned Team ID before `sctl ingest` sends the binary into
/// the sibling VM's `s-vsockd` quarantine.
public enum CodeSignVerifier {
    public struct VerifiedMachO: Sendable {
        public let cdhashHex: String
        public let teamIdentifier: String
        public let signingIdentifier: String
    }

    public enum VerifyError: Error, CustomStringConvertible {
        case createFailed(OSStatus)
        case requirementCompileFailed(OSStatus)
        case signatureInvalid(OSStatus, String)
        case infoFailed(OSStatus)
        case missingCDHash
        case teamMismatch(expected: String, actual: String?)

        public var description: String {
            switch self {
            case .createFailed(let s): return "SecStaticCodeCreateWithPath failed (\(s))"
            case .requirementCompileFailed(let s): return "SecRequirementCreateWithString failed (\(s))"
            case .signatureInvalid(let s, let m): return "SecStaticCodeCheckValidity failed (\(s)): \(m)"
            case .infoFailed(let s): return "SecCodeCopySigningInformation failed (\(s))"
            case .missingCDHash: return "CodeSigning dictionary missing unique CDHash"
            case .teamMismatch(let exp, let got):
                return "TeamIdentifier \(got ?? "nil") != expected \(exp)"
            }
        }
    }

    public static func verify(binaryURL: URL, expectedTeamID: String) throws -> VerifiedMachO {
        let cleanTeam = expectedTeamID.filter { $0.isASCII && ($0.isLetter || $0.isNumber) }
        precondition(!cleanTeam.isEmpty && cleanTeam == expectedTeamID, "invalid Team ID")

        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(binaryURL as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            throw VerifyError.createFailed(createStatus)
        }

        let reqString = "anchor apple generic and certificate leaf[subject.OU] = \"\(cleanTeam)\""
        var requirement: SecRequirement?
        let reqStatus = SecRequirementCreateWithString(reqString as CFString, [], &requirement)
        guard reqStatus == errSecSuccess, let req = requirement else {
            throw VerifyError.requirementCompileFailed(reqStatus)
        }

        var cfErr: Unmanaged<CFError>?
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        let validStatus = SecStaticCodeCheckValidityWithErrors(code, flags, req, &cfErr)
        if validStatus != errSecSuccess {
            let detail = cfErr?.takeRetainedValue().localizedDescription ?? "unknown"
            throw VerifyError.signatureInvalid(validStatus, detail)
        }

        var infoRef: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &infoRef
        )
        guard infoStatus == errSecSuccess, let info = infoRef as? [String: Any] else {
            throw VerifyError.infoFailed(infoStatus)
        }

        let team = info[kSecCodeInfoTeamIdentifier as String] as? String
        guard team == cleanTeam else {
            throw VerifyError.teamMismatch(expected: cleanTeam, actual: team)
        }
        guard let cdhashData = info[kSecCodeInfoUnique as String] as? Data else {
            throw VerifyError.missingCDHash
        }
        let ident = (info[kSecCodeInfoIdentifier as String] as? String) ?? ""
        let hex = cdhashData.map { String(format: "%02x", $0) }.joined()
        return VerifiedMachO(cdhashHex: hex, teamIdentifier: cleanTeam, signingIdentifier: ident)
    }
}
#endif
