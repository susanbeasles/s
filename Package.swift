// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SVMHost",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "svm-host", targets: ["SVMHost"])
    ],
    targets: [
        .executableTarget(
            name: "SVMHost",
            path: "Sources/SVMHost",
            linkerSettings: [
                .linkedFramework("Virtualization"),
                .linkedFramework("Security"),
            ]
        )
    ]
)
