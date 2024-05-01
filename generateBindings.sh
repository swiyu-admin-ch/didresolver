cargo build --release
cargo run --bin uniffi-bindgen generate --library target/release/libdidresolver.dylib --language kotlin --out-dir bindings/kotlin
cargo run --bin uniffi-bindgen generate --library target/release/libdidresolver.dylib --language swift --out-dir bindings/swift/files
cargo run --bin uniffi-bindgen generate --library target/release/libdidresolver.dylib --language python --out-dir bindings/python