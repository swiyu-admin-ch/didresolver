cargo build --release
cargo run --bin uniffi-bindgen generate --library target/release/libdidresolver.so --language kotlin --out-dir bindings/kotlin
cp target/release/libdidresolver.so bindings/kotlin