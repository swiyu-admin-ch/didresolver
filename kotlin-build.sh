cargo clean
cargo build --release
# For details, see .github/workflows/build_kotlin.yml
cargo run --bin uniffi-bindgen generate --library target/release/libdidresolver.so --language kotlin --out-dir bindings/kotlin
cp target/release/libdidresolver.so bindings/kotlin