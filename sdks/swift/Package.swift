// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Rembrane",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "Rembrane", targets: ["Rembrane"])],
    targets: [
        .target(name: "Rembrane"),
        .executableTarget(
            name: "RembraneSmoke",
            dependencies: ["Rembrane"],
            path: "Tests/RembraneSmoke"
        ),
    ]
)
