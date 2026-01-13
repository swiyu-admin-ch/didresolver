import ch.admin.eid.did_sidekicks.*

// Execute these tests by running: cargo test uniffi_foreign_language_testcase_test_did_sidekicks_ed25519_kts

try {

    // From https://www.w3.org/TR/vc-di-eddsa/#test-vectors
    var signing_key = Ed25519SigningKey.fromMultibase("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq")
    var verifying_key = signing_key.getVerifyingKey()
    assert(verifying_key.toMultibase() == "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")

    assert(signing_key
        // From https://www.w3.org/TR/vc-di-eddsa/#example-combine-hashes-of-proof-options-and-credential-hex-1
        .signHex("66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19")
        .toHex()
        // From https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-hex-1
        .equals("407cd12654b33d718ecbb99179a1506daaa849450bf3fc523cce3e1c96f8b80351da3f253d725c6f00b07c9e5448d50b3ef78012b9ab54255116d069c6dd2808"))

    assert(signing_key
        // From https://www.w3.org/TR/vc-di-eddsa/#example-combine-hashes-of-proof-options-and-credential-hex-1
        .signHex("66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19")
        .toMultibase()
        // From https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
        .equals("z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"))

    assert(Ed25519Signature
        // From https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-hex-1
        .fromHex("407cd12654b33d718ecbb99179a1506daaa849450bf3fc523cce3e1c96f8b80351da3f253d725c6f00b07c9e5448d50b3ef78012b9ab54255116d069c6dd2808")
        .toHex()
        .equals("407cd12654b33d718ecbb99179a1506daaa849450bf3fc523cce3e1c96f8b80351da3f253d725c6f00b07c9e5448d50b3ef78012b9ab54255116d069c6dd2808"));

    assert(Ed25519Signature
        // https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
        .fromMultibase("z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX")
        .toMultibase()
        .equals("z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"));

    signing_key = Ed25519SigningKey.fromPkcs8Pem("""
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPf7l3y23VrVWsZVrsN2+YuICyrZeAKIZfyyp6iSolRI
-----END PRIVATE KEY-----
""") // z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD

    verifying_key = Ed25519VerifyingKey.fromPublicKeyPem("""
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA8ETLwQBKgk9fM2V0tQV5AdjrMvetLrgj5C+FOmYGTJg=
-----END PUBLIC KEY-----
""") // z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP

    val message = "This is a test of the tsunami alert system."
    var signature = signing_key.sign(message)
    signing_key.getVerifyingKey().verifyStrict(message, signature)
    verifying_key.verifyStrict(message, signature)

    signing_key = Ed25519SigningKey.readPkcs8PemFile("../did_sidekicks/test_data/keys/private.pem") // z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD
    verifying_key = Ed25519VerifyingKey.readPublicKeyPemFile("../did_sidekicks/test_data/keys/public.pem") // z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP
    signature = signing_key.sign(message)
    signing_key.getVerifyingKey().verifyStrict(message, signature)
    verifying_key.verifyStrict(message, signature)

} catch (e: DidSidekicksException) {
    //assert(e !is DidSidekicksException)
    throw RuntimeException("No exception expected, but got: " + e)
}
