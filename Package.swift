// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DVTSecurity",

    platforms: [
        .macOS(.v10_12),
        .iOS(.v10),
    ],

    products: [
        .library(name: "DVTSecurity",
                 targets: ["DVTSecurity"]),
    ],

    targets: [
        .target(
            name: "DVTSecurity",
            dependencies: [],
            path: "Sources"
        ),
        .testTarget(
            name: "DVTSecurityTests",
            dependencies: ["DVTSecurity"]
        ),
    ],

    swiftLanguageVersions: [.v5]
)
