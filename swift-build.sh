echo ">> Cleanup"
cargo clean
echo ">> Build release"
cargo build --release

echo ">> Generate bindings"
cargo run --bin uniffi-bindgen generate --library target/release/libdidresolver.dylib --language swift --out-dir bindings/swift/files

echo ">> Build Swift package"
# Only Tier: 2 (without Host Tools) targets (according to https://doc.rust-lang.org/rustc/platform-support/apple-ios.html)
# Apple iOS on ARM64
cargo build --release --target aarch64-apple-ios
# Apple iOS Simulator on ARM64
cargo build --release --target aarch64-apple-ios-sim
# Apple iOS Simulator on 64-bit x86
cargo build --release --target x86_64-apple-ios

# CAUTION In case of iOS Simulator, all the simulator-relevant libs must be combined into one single "fat" static library
lipo -create -output target/libdidresolver.a \
  target/aarch64-apple-ios-sim/release/libdidresolver.a \
  target/x86_64-apple-ios/release/libdidresolver.a

cat bindings/swift/files/didtoolboxFFI.modulemap >> bindings/swift/files/module.modulemap
cat bindings/swift/files/didFFI.modulemap >> bindings/swift/files/module.modulemap
rm -r bindings/swift/didresolver.xcframework

echo ">> Build XFC framework"
xcodebuild -create-xcframework \
  -library ./target/libdidresolver.a \
  -headers ./bindings/swift/files \
  -library ./target/aarch64-apple-ios/release/libdidresolver.a \
  -headers ./bindings/swift/files \
  -output "./bindings/swift/didresolver.xcframework"

rm bindings/swift/files/module.modulemap

echo ">> Generate swift package structure"
mkdir output
mkdir output/DidResolverWrapper
mkdir output/DidResolverWrapper/include
touch output/DidResolverWrapper/include/dummy.h
touch output/DidResolverWrapper/dummy.m
cp -r bindings/swift/didresolver.xcframework output/
mkdir output/swift-sources
cp -r bindings/swift/didresolver.xcframework/ios-arm64/Headers/*.swift output/swift-sources
cat <<-EOF > output/Package.swift
// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "DidResolver",
    platforms: [.iOS(.v15)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(name: "DidResolver",targets:["DidResolverSources"]),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "DidResolverWrapper",
            dependencies:[
                .target(name:"DidResolver", condition: .when(platforms: [.iOS]))
            ],
            path: "DidResolverWrapper"
        ),
        .binaryTarget(
            name: "DidResolver",
            path: "./didresolver.xcframework"
        ),
        .target(
            name: "DidResolverSources",
            dependencies: ["DidResolverWrapper"],
            path: "swift-sources"
        )
    ]
)
EOF
