import ch.admin.eid.didresolver.*
import ch.admin.eid.did_sidekicks.*
//import ch.admin.eid.didtoolbox.*

import java.io.IOException
import java.net.URI
import java.net.URISyntaxException
import javax.net.ssl.HttpsURLConnection

var did = ""

var didObj: Did? = null

try {

    // ----------------------------- WEBVH --------------------------------------

    did = "did:webvh:QmXi8p2LNXA6kbc2brwdpXwGETHCrPoFk15yPbLaAu27Pj:gist.githubusercontent.com:vst-bit:20c3f59d8179e324a6e29aef45240db4:raw:7870280f80dfcfb7459ee1488df4ab33f2bcf709"

    didObj = Did(did) // may throw DidResolveException
    assert(didObj?.getMethod() == DidMethod.WEBVH)
    assert(didObj?.getScid() == "QmXi8p2LNXA6kbc2brwdpXwGETHCrPoFk15yPbLaAu27Pj")

    var httpsUrl = didObj?.getHttpsUrl()
    assert(httpsUrl != null)
    assert(httpsUrl == "https://gist.githubusercontent.com/vst-bit/20c3f59d8179e324a6e29aef45240db4/raw/7870280f80dfcfb7459ee1488df4ab33f2bcf709/did.jsonl")

    var didLog = fetchDidLog(httpsUrl) // may throw IOException, URISyntaxException
    assert(didLog != null)

    var didDoc = didObj?.resolve(didLog)
    assertDidDoc(didDoc)

    assert(didDoc?.getId() == "did:webvh:QmXi8p2LNXA6kbc2brwdpXwGETHCrPoFk15yPbLaAu27Pj:gist.githubusercontent.com:vst-bit:8d8247633dbc5836324a81725c1216d8:raw:fde1612e271991f23e814943d7636a4dbac6752b")

    // ----------------------------- TDW --------------------------------------

    did = "did:tdw:QmRjT8JCbQkEffVBWSbQd8nbMVNfAxiXStLPmqkQUWcsfv:gist.githubusercontent.com:vst-bit:32b64cfac9075b2a3ab7301b772bcdef:raw:8b4bd2b715101d5b69b3395f5c560c37e1ae9992"

    didObj = Did(did) // may throw DidResolveException
    assert(didObj?.getMethod() == DidMethod.TDW)
    assert(didObj?.getScid() == "QmRjT8JCbQkEffVBWSbQd8nbMVNfAxiXStLPmqkQUWcsfv")

    httpsUrl = didObj?.getHttpsUrl()
    assert(httpsUrl != null)
    assert(httpsUrl == "https://gist.githubusercontent.com/vst-bit/32b64cfac9075b2a3ab7301b772bcdef/raw/8b4bd2b715101d5b69b3395f5c560c37e1ae9992/did.jsonl")

    didLog = fetchDidLog(httpsUrl) // may throw IOException, URISyntaxException
    assert(didLog != null)

    didDoc = didObj?.resolve(didLog)
    assertDidDoc(didDoc)

    assert(didDoc?.getId() == "did:tdw:QmRjT8JCbQkEffVBWSbQd8nbMVNfAxiXStLPmqkQUWcsfv:gist.githubusercontent.com:vst-bit:8d8247633dbc5836324a81725c1216d8:raw:fde1612e271991f23e814943d7636a4dbac6752b")

} catch (e: Exception) {
    assert(e !is DidResolveException)
    assert(e !is IOException)
    assert(e !is URISyntaxException)
    assert(e !is DidResolveException)
    throw RuntimeException("No exception expected")
} finally {
    didObj?.close()
}

@Throws(IOException::class, URISyntaxException::class)
private fun fetchDidLog(httpsUrl: String?): String {
    val content = StringBuilder()
    (URI(httpsUrl).toURL().openConnection() as HttpsURLConnection).inputStream.bufferedReader().use { reader ->
        var inputLine: String?
        while (reader.readLine().also { inputLine = it } != null) {
            content.append(inputLine)
        }
    }
    return content.toString()
}

private fun assertDidDoc(didDoc: DidDoc?) {
    assert(didDoc != null)
    val didDocId = didDoc?.getId();
    assert(didDoc?.getAuthentication() != null)
    assert(didDoc?.getAssertionMethod() != null)
    val verificationMethod = didDoc?.getVerificationMethod()
    assert(verificationMethod != null)
    assert(verificationMethod?.size != 0)
    val verificationMethod0 = verificationMethod?.get(0)
    assert(verificationMethod0 != null)
    assert(verificationMethod0?.publicKeyJwk != null)
    assert(verificationMethod0?.id == didDocId + "#" + verificationMethod0?.publicKeyJwk?.kid)
    assert(verificationMethod0?.verificationType == VerificationType.JSON_WEB_KEY2020)
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
