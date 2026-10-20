// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AppGuardApple",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [.library(name: "AppGuardApple", targets: ["AppGuardApple"])],
    targets: [
        .target(name: "AppGuardApple", resources: [.copy("Resources/PrivacyInfo.xcprivacy")]),
        .testTarget(name: "AppGuardAppleTests", dependencies: ["AppGuardApple"])
    ]
)
