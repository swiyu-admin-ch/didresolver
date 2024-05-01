cargo build --release --target aarch64-apple-ios-sim
cargo build --release --target aarch64-apple-ios
cp bindings/swift/files/didFFI.modulemap bindings/swift/files/module.modulemap
rm -r bindings/swift/didresolver.xcframework
xcodebuild -create-xcframework -library ./target/aarch64-apple-ios-sim/release/libdidresolver.a -headers ./bindings/swift/files -library ./target/aarch64-apple-ios/release/libdidresolver.a -headers ./bindings/swift/files -output "./bindings/swift/didresolver.xcframework"
rm bindings/swift/files/module.modulemap