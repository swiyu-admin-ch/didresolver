use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use did_sidekicks::did_doc::{DidDocNormalized, VerificationMethod, VerificationType};
use rand::seq::SliceRandom;

pub fn criterion_benchmark_to_did_doc(c: &mut Criterion) {
    let inputs = [100, 500, 1000, 1500, 2000, 2500, 3000];

    let mut group = c.benchmark_group("did_sidekicks");
    group
        .significance_level(0.01)
        .confidence_level(0.99)
        //.noise_threshold(0.01)
        //sampling_mode(SamplingMode::Auto) // intended for long-running benchmarks.
        //.nresamples(4000)
        //.measurement_time(std::time::Duration::from_secs(10))
        //.sample_size(25)
        //.warm_up_time(Duration::from_secs(5))
    ;

    let documents: Vec<_> = inputs
        .iter()
        .map(|size| {
            let methods: Vec<_> = (0..*size)
                .map(|i| VerificationMethod {
                     id: format!("did:webvh:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#{}", i),
                    controller: i.to_string(),
                    verification_type: VerificationType::Multikey,
                    public_key_multibase: Some(format!("multibase key {}", size)),
                    public_key_jwk: None,
                })
                .collect();
            let method_references: Vec<_> = (0..*size).map(|i| format!("did:webvh:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#{}", i)).collect();
            let mut doc_normalized = DidDocNormalized {
                context: Vec::new(),
                id: format!("Document with {} verification methods", size),
                verification_method: methods,
                authentication: method_references.clone(),
                capability_invocation: method_references.clone(),
                capability_delegation: method_references.clone(),
                assertion_method: method_references.clone(),
                key_agreement: method_references.clone(),
                controller: None,
                deactivated: None,
                profile_version: None,
            };
            doc_normalized.verification_method.shuffle(&mut rand::rngs::OsRng);
            doc_normalized.authentication.shuffle(&mut rand::rngs::OsRng);
            doc_normalized.capability_invocation.shuffle(&mut rand::rngs::OsRng);
            doc_normalized.capability_delegation.shuffle(&mut rand::rngs::OsRng);
            doc_normalized.assertion_method.shuffle(&mut rand::rngs::OsRng);
            doc_normalized.key_agreement.shuffle(&mut rand::rngs::OsRng);
            (size, doc_normalized)
        })
        .collect();

    for (size, document) in documents {
        group.bench_function(BenchmarkId::new("DidDoc_document_conversion", size), |b| {
            b.iter(|| {
                let doc = document.to_did_doc().unwrap();
                let _ = doc;
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    criterion_benchmark_to_did_doc,
);
criterion_main!(benches);
