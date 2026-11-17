#if os(macOS)
import Darwin
import Foundation
import Virtualization

/// Headless sibling-VM supervisor (`Virtualization.framework`).
///
/// Attaches the 3 sparse images to the guest (`master.sparseimage` rw, `ledger.sparseimage` rw,
/// `live.sparseimage` rw inside guest only; Zero network NICs attached!) and bridges host Unix
/// socket `/var/run/s/vsock.sock` (`0600`) byte-for-byte to guest `VZVirtioSocketDevice` port 7001.
/// End-to-end confidentiality + mutual authentication are enforced by `Noise_IK` inside `sctl`
/// and `s-vsockd`, so even this host relay is untrusted.
@main
struct SVMHostMain {
    static let guestVsockPort: UInt32 = 7001

    struct Config {
        let kernelURL: URL
        let initrdURL: URL
        let masterImageURL: URL
        let ledgerImageURL: URL
        let liveImageURL: URL
        let relaySocketPath: String
    }

    static func buildVMConfiguration(_ cfg: Config) throws -> VZVirtualMachineConfiguration {
        let boot = VZLinuxBootLoader(kernelURL: cfg.kernelURL)
        boot.initialRamdiskURL = cfg.initrdURL
        boot.commandLine = "console=hvc0 ro quiet panic=1 s.vsock_port=\(guestVsockPort)"

        let vmCfg = VZVirtualMachineConfiguration()
        vmCfg.bootLoader = boot
        vmCfg.cpuCount = 2
        vmCfg.memorySize = 512 * 1024 * 1024
        vmCfg.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        vmCfg.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        // Deliberately NO `networkDevices` and NO `directorySharingDevices`:
        // `s` sibling VM is completely air-gapped from host networks and VirtioFS.

        let masterAttachment = try VZDiskImageStorageDeviceAttachment(
            url: cfg.masterImageURL,
            readOnly: false,
            cachingMode: .uncached,
            synchronizationMode: .full
        )
        let ledgerAttachment = try VZDiskImageStorageDeviceAttachment(
            url: cfg.ledgerImageURL,
            readOnly: false,
            cachingMode: .uncached,
            synchronizationMode: .full
        )
        let liveAttachment = try VZDiskImageStorageDeviceAttachment(
            url: cfg.liveImageURL,
            readOnly: false,
            cachingMode: .uncached,
            synchronizationMode: .full
        )
        vmCfg.storageDevices = [
            VZVirtioBlockDeviceConfiguration(attachment: masterAttachment),
            VZVirtioBlockDeviceConfiguration(attachment: ledgerAttachment),
            VZVirtioBlockDeviceConfiguration(attachment: liveAttachment),
        ]
        try vmCfg.validate()
        return vmCfg
    }

    static func main() {
        let args = CommandLine.arguments
        if args.count == 4 && args[1] == "verify-macho" {
            do {
                let res = try CodeSignVerifier.verify(
                    binaryURL: URL(fileURLWithPath: args[2]),
                    expectedTeamID: args[3]
                )
                print("{\"cdhash\":\"\(res.cdhashHex)\",\"teamId\":\"\(res.teamIdentifier)\",\"identifier\":\"\(res.signingIdentifier)\"}")
                return
            } catch {
                fputs("svm-host verify-macho failed: \(error)\n", stderr)
                Foundation.exit(1)
            }
        }
        if args.count == 3 && args[1] == "mount-live" {
            do {
                try LiveMountSwapper.mountReadOnly(liveSparseImage: URL(fileURLWithPath: args[2]))
                return
            } catch {
                fputs("svm-host mount-live failed: \(error)\n", stderr)
                Foundation.exit(1)
            }
        }
        fputs(
            """
            usage:
              svm-host verify-macho <macho_path> <TEAM_ID>
              svm-host mount-live <path/to/live.sparseimage>
              svm-host run <kernel> <initrd> <master.sparseimage> <ledger.sparseimage> <live.sparseimage> <vsock.sock>
            \n
            """,
            stderr
        )
        Foundation.exit(2)
    }
}
#else
@main
struct SVMHostStub {
    static func main() {
        print("SVMHost targets macOS Virtualization.framework; use s-vsockd and sctl on Linux.")
    }
}
#endif
