// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DVTSecurity",
    
    platforms: [
        .macOS(.v11),
        .iOS(.v13)
    ],
    
    products: [
        .library(
            name: "DVTSecurity",
            targets: ["DVTSecurity"]
        )
    ],
    
    dependencies: [
    ],
    
    targets: [
        .target(
            name: "DVTSecurity",
            dependencies: [],
            path: "Sources",
            linkerSettings: [
                .linkedFramework("Security")
            ]
        ),
    
        .testTarget(
            name: "DVTSecurityTests",
            dependencies: ["DVTSecurity"]
        )
    ]
)
