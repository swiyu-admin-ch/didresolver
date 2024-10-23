# CAUTION Ensure the both required "targets" (rustc --print target-list) are already installed e.g.
# rustup target add aarch64-apple-ios-sim aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
cargo build --release --target aarch64-apple-ios
# HINT To ensure the architecture is correct, just use the command "lipo -info" e.g.
# lipo -info target/aarch64-apple-ios*/release/libdidresolver.a                                                                                                                                                                                            ─╯
# Non-fat file: target/aarch64-apple-ios-sim/release/libdidresolver.a is architecture: arm64
# Non-fat file: target/aarch64-apple-ios/release/libdidresolver.a is architecture: arm64
cp bindings/swift/files/didFFI.modulemap bindings/swift/files/module.modulemap
rm -rf bindings/swift/didresolver.xcframework
xcodebuild -create-xcframework -library ./target/aarch64-apple-ios-sim/release/libdidresolver.a -headers ./bindings/swift/files -library ./target/aarch64-apple-ios/release/libdidresolver.a -headers ./bindings/swift/files -output "./bindings/swift/didresolver.xcframework"
rm bindings/swift/files/module.modulemap
# TODO Manually copy the generated bindings/swift/didresolver.xcframework directory into the repo e-id-admin/didresolver-swift
# TODO Manually copy the generated bindings/swift/didresolver.xcframework directory into the repo e-id-admin/didresolver-swift