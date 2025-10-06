#[expect(clippy::unwrap_used, reason = "..")]
fn main() {
    uniffi::generate_scaffolding("src/did.udl").unwrap();
}
