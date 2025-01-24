cargo clean
cargo build --release
# For details, see .github/workflows/build_kotlin-android.yml
cargo ndk -o ./bindings/kotlin/jniLibs --manifest-path ./Cargo.toml -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 build --release
cargo run --bin uniffi-bindgen generate --library target/release/libdidresolver.so --language kotlin --out-dir bindings/kotlin