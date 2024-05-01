cargo build --release
cargo build --release --target=x86_64-pc-windows-gnu
TARGET_CC=x86_64-unknown-linux-gnu cargo build --release --target x86_64-unknown-linux-gnu
cp target/release/libdidresolver.dylib bindings/python
cp target/x86_64-unknown-linux-gnu/release/libdidresolver.so bindings/python
cp target/x86_64-pc-windows-gnu/release/libdidresolver.dll bindings/python