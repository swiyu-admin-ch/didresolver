echo ">>"; echo ">> Cleanup"; echo ">>"
cargo clean
echo ">>"; echo ">> Build release"; echo ">>"
cargo build --release

# Check for arguments
if [ $# -eq 0 ]; then
    echo "No arguments provided."
    echo "   First  argument has to be a (semantic) version, e.g. '1.2.3'"
    echo "   Second argument has to be a Swift package name, e.g. 'DidResolver'"
    echo "   Third  argument has to be a XCFramework name,   e.g. 'didresolver'"
    exit 1
fi

version=$1
swift_package_name=$2
xcframework_name=$3

echo ">>"; echo ">> Generating UniFFI bindings for Swift package '${swift_package_name}' v${version}..."; echo ">>"
cargo run --bin uniffi-bindgen generate \
          --library target/release/lib${xcframework_name}.dylib \
          --language swift \
          --out-dir bindings/swift/files

# Only Tier: 2 (without Host Tools) targets (according to https://doc.rust-lang.org/rustc/platform-support/apple-ios.html)
# Control the minimum iOS version of your Rust library via the IPHONEOS_DEPLOYMENT_TARGET environment variable.
# Rust uses these values to determine the OS version passed to the linker via the -target flag.
# See https://doc.rust-lang.org/stable/rustc/platform-support/apple-ios.html?highlight=IPHONEOS_DEPLOYMENT_TARGET#os-version
echo ">>"; echo ">> Building for Apple iOS on ARM64..."; echo ">>"
IPHONEOS_DEPLOYMENT_TARGET=15.0 cargo build --release --target aarch64-apple-ios
echo ">>"; echo ">> Building for Apple iOS Simulator on ARM64..."; echo ">>"
IPHONEOS_DEPLOYMENT_TARGET=15.0 cargo build --release --target aarch64-apple-ios-sim
echo ">>"; echo ">> Building for Apple iOS Simulator on 64-bit x86..."; echo ">>"
IPHONEOS_DEPLOYMENT_TARGET=15.0 cargo build --release --target x86_64-apple-ios

# CAUTION In case of iOS Simulator, all the simulator-relevant libs must be combined into one single "fat" static library
echo ">>"; echo ">> Building a single 'fat' static library 'lib${xcframework_name}'..."; echo ">>"
lipo -create -output target/lib${xcframework_name}.a \
  target/aarch64-apple-ios-sim/release/lib${xcframework_name}.a \
  target/x86_64-apple-ios/release/lib${xcframework_name}.a

cat bindings/swift/files/did_sidekicksFFI.modulemap \
    bindings/swift/files/did_tdwFFI.modulemap       \
    bindings/swift/files/did_webvhFFI.modulemap     \
    bindings/swift/files/didFFI.modulemap           >> bindings/swift/files/module.modulemap

rm -r bindings/swift/${xcframework_name}.xcframework &>/dev/null

echo ">>"; echo ">> Building the XFC framework '${xcframework_name}'..."; echo ">>"
xcodebuild -create-xcframework \
  -library ./target/lib${xcframework_name}.a \
  -headers ./bindings/swift/files \
  -library ./target/aarch64-apple-ios/release/lib${xcframework_name}.a \
  -headers ./bindings/swift/files \
  -output "./bindings/swift/${xcframework_name}.xcframework"

rm bindings/swift/files/module.modulemap

# Preventing multiple modulemap build error (inspired by https://github.com/jessegrosjean/module-map-error and https://github.com/jessegrosjean/swift-cargo-problem)
echo ">>"; echo ">> Preventing 'multiple modulemap build error'..."; echo ">>"
cd bindings/swift/${xcframework_name}.xcframework
mkdir ios-arm64/Headers/${xcframework_name} \
      ios-arm64_x86_64-simulator/Headers/${xcframework_name}
mv ios-arm64/Headers/*.*                  ios-arm64/Headers/${xcframework_name}/
mv ios-arm64_x86_64-simulator/Headers/*.* ios-arm64_x86_64-simulator/Headers/${xcframework_name}/
# ZIP the XCFramework directory to create an release asset
cd ..
zip -r ${xcframework_name}.xcframework.zip ${xcframework_name}.xcframework
# The checksum of the ZIP archive that contains the XCFramework, as required for any 'binaryTarget'
# See https://developer.apple.com/documentation/xcode/distributing-binary-frameworks-as-swift-packages
checksum=$(swift package compute-checksum ${xcframework_name}.xcframework.zip)
echo ">>"; echo ">> Checksum of the ZIP archive containing the XCFramework: ${checksum}"; echo ">>"
cd - &>/dev/null

echo ">>"; echo ">> Generating the Swift package structure..."; echo ">>"
mkdir output
cp -r bindings/swift/${xcframework_name}.xcframework output/
mkdir -p output/Sources/${swift_package_name}
cp -r bindings/swift/${xcframework_name}.xcframework/ios-arm64/Headers/${xcframework_name}/*.swift output/Sources/${swift_package_name}

cat <<-EOF > output/Package.swift
// swift-tools-version:5.3
import PackageDescription

let version = "${version}"
let checksum = "${checksum}"

let package = Package(
    name: "${swift_package_name}",
    platforms: [.iOS(.v14)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "${swift_package_name}",
            targets: ["${swift_package_name}", "${swift_package_name}RemoteBinaryPackage"]),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "${swift_package_name}"
        ),
        .binaryTarget(
            name: "${swift_package_name}RemoteBinaryPackage",
            url: "https://github.com/swiyu-admin-ch/didresolver-swift/releases/download/\(version)/${xcframework_name}.xcframework.zip",
            checksum: "\(checksum)"
        )
    ]
)
EOF
