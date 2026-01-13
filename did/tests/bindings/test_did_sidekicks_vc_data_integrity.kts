import ch.admin.eid.did_sidekicks.*

// Execute these tests by running: cargo test uniffi_foreign_language_testcase_test_did_sidekicks_vc_data_integrity_kts

try {

    // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
    val crypto_suite = EddsaJcs2022Cryptosuite.fromSigningKey(
        Ed25519SigningKey.fromMultibase("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"),
    )

    // https://www.w3.org/TR/vc-di-eddsa/#test-vectors
    // https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022

    // From https://www.w3.org/TR/vc-di-eddsa/#example-credential-without-proof-0
    val credentials_without_proof_obj = """
{
     "@context": [
         "https://www.w3.org/ns/credentials/v2",
         "https://www.w3.org/ns/credentials/examples/v2"
     ],
     "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
     "type": ["VerifiableCredential", "AlumniCredential"],
     "name": "Alumni Credential",
     "description": "A minimum viable example of an Alumni Credential.",
     "issuer": "https://vc.example/issuers/5678",
     "validFrom": "2023-01-01T00:00:00Z",
     "credentialSubject": {
         "id": "did:example:abcdefgh",
         "alumniOf": "The School of Examples"
     }
}
"""

    val doc_hash = JcsSha256Hasher.build().encodeHex(credentials_without_proof_obj)
    // From https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-credential-without-proof-hex-0
    assert(doc_hash == "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19")

    val secured_document = crypto_suite.addProof(
        credentials_without_proof_obj,
        // From https://www.w3.org/TR/vc-di-eddsa/#example-proof-options-document-1
        CryptoSuiteProofOptions.newEddsaJcs2022(
            "2023-02-24T23:36:38Z",
            "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            "assertionMethod",
            listOf(
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2",
            ),
            null, // no challenge in this example
        )
    )

    // From https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
    assert(secured_document.contains("""proofValue":"z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"""))

    // From https://www.w3.org/TR/vc-di-eddsa/#example-signed-credential-0
    val proof = DataIntegrityProof.fromJsonString("""
[{
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "proofPurpose": "assertionMethod",
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "proofValue": "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"
}]
""")

    // sanity check (no exception should be thrown)
    crypto_suite.verifyProof(proof, doc_hash)

} catch (e: DidSidekicksException) {
    //assert(e !is DidSidekicksException)
    throw RuntimeException("No exception expected, but got: " + e)
}
