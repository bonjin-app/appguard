// swift-tools-version: 5.9
import PackageDescription

// Local conformance tool; not part of the SDK's exported products.
let package = Package(
    name: "AppGuardAppleInteropProbe",
    platforms: [.macOS(.v13)],
    dependencies: [.package(path: "../..")],
    targets: [.executableTarget(name: "InteropProbe", dependencies: [.product(name: "AppGuardApple", package: "apple")])]
)
