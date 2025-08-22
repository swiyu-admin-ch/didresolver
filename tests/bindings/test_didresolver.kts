import ch.admin.eid.didresolver.*
//import ch.admin.eid.didtoolbox.*

var did = "did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"

var didObj: Did? = null

try {
    didObj = Did(did) // may throw DidResolveException
    val url = didObj?.getHttpsUrl()
    assert(url != null)
    assert(url == "https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085/did.jsonl")
} catch (e: Exception) {
    assert(e !is DidResolveException)
    throw RuntimeException("No exception expected")
} finally {
    didObj?.close()
}

did = "did:tdwx:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"

try {
    didObj = Did(did) // may throw DidResolveException
    throw RuntimeException("Should have thrown a DidResolveException!")
} catch (e: Exception) {
    assert(e is DidResolveException)
} finally {
    didObj?.close()
}

did = "did:webvh:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"

try {
    didObj = Did(did) // may throw DidResolveException
    val url = didObj?.getHttpsUrl()
    assert(url != null)
    assert(url == "https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085/did.jsonl")
} catch (e: Exception) {
    assert(e !is DidResolveException)
    throw RuntimeException("No exception expected")
} finally {
    didObj?.close()
}

did = "did:webvhx:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"

try {
    didObj = Did(did) // may throw DidResolveException
    throw RuntimeException("Should have thrown a DidResolveException!")
} catch (e: Exception) {
    assert(e is DidResolveException)
} finally {
    didObj?.close()
}

// Ensure the kotlin version of deinit doesn't crash, and is idempotent.
didObj?.destroy()
didObj?.destroy()
