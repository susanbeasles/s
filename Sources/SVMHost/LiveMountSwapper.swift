#if os(macOS)
import Foundation

/// Manages the host-side read-only mount of `live.sparseimage` onto `/s`
/// (anchored in `/etc/synthetic.conf` as `s\tSystem/Volumes/Data/.s-mount`).
///
/// Security invariants:
/// - `master.sparseimage` and `ledger.sparseimage` are NEVER attached on the macOS host;
///   only the sibling Linux VM attaches them over `VZVirtioBlockDeviceConfiguration`.
/// - `live.sparseimage` is attached strictly `-readonly -nobrowse` and mounted with
///   `rdonly,nobrowse,owners,nodev,nosuid`.
public enum LiveMountSwapper {
    public static let syntheticAnchor = "/s"
    public static let mountOptions = "rdonly,nobrowse,owners,nodev,nosuid"

    public enum MountError: Error, CustomStringConvertible {
        case missingSyntheticRoot
        case forbiddenImageName(String)
        case commandFailed(executable: String, status: Int32, stderr: String)

        public var description: String {
            switch self {
            case .missingSyntheticRoot:
                return "/s synthetic root missing; add 's\\tSystem/Volumes/Data/.s-mount' to /etc/synthetic.conf"
            case .forbiddenImageName(let n):
                return "refusing to host-attach non-live volume: \(n)"
            case .commandFailed(let exe, let code, let err):
                return "\(exe) exited \(code): \(err)"
            }
        }
    }

    public static func mountReadOnly(liveSparseImage: URL) throws {
        let name = liveSparseImage.lastPathComponent
        guard name == "live.sparseimage" else {
            throw MountError.forbiddenImageName(name)
        }
        guard FileManager.default.fileExists(atPath: syntheticAnchor) else {
            throw MountError.missingSyntheticRoot
        }
        _ = try? run("/usr/sbin/diskutil", ["unmount", "force", syntheticAnchor])
        _ = try run(
            "/usr/bin/hdiutil",
            [
                "attach",
                "-readonly",
                "-nobrowse",
                "-mountrequired",
                "-mountpoint", syntheticAnchor,
                "-mountrandom", "/System/Volumes/Data/.s-staging",
                liveSparseImage.path,
            ]
        )
        _ = try run("/sbin/mount", ["-u", "-o", mountOptions, syntheticAnchor])
    }

    @discardableResult
    private static func run(_ executable: String, _ arguments: [String]) throws -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: executable)
        proc.arguments = arguments
        let out = Pipe()
        let err = Pipe()
        proc.standardOutput = out
        proc.standardError = err
        try proc.run()
        proc.waitUntilExit()
        let stdoutStr = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderrStr = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard proc.terminationStatus == 0 else {
            throw MountError.commandFailed(
                executable: executable,
                status: proc.terminationStatus,
                stderr: stderrStr
            )
        }
        return stdoutStr
    }
}
#endif
