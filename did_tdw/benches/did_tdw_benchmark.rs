// SPDX-License-Identifier: MIT

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use did_sidekicks::did_jsonschema::{DidLogEntryJsonSchema, DidLogEntryValidator};
use did_tdw::did_tdw::TrustDidWeb;
use did_tdw::did_tdw_jsonschema::TrustDidWebDidLogEntryJsonSchema;
use rayon::prelude::*;
use std::fs;
use std::path::Path;

pub fn criterion_benchmark_setup(_: &mut Criterion) {
    // On MacOS, this should match the result of running `sysctl -a machdep.cpu` command
    let available_parallelism = std::thread::available_parallelism().unwrap().get();

    // Calling `build_global` is not recommended, except in two scenarios:
    // - You wish to change the default configuration.
    // - You are running a benchmark, in which case initializing may yield slightly more consistent results,
    // since the worker threads will already be ready to go even in the first iteration. But this cost is minimal.
    //
    // Initialization of the global thread pool happens exactly once.
    // Once started, the configuration cannot be changed.
    // Therefore, if you call build_global a second time, it will return an error.
    rayon::ThreadPoolBuilder::new()
        // feel free to set the downscale factor manually, e.g. 2,3,4,6 etc.
        .num_threads(available_parallelism / 1)
        .build_global()
        .unwrap();
    //println!("Global thread pool (rayon) initialized");
}

pub fn criterion_benchmark_did_tdw(c: &mut Criterion) {
    let inputs = [5, 10, 50, 100, 200, 300, 400];

    let mut group = c.benchmark_group("did_tdw");
    group
        .significance_level(0.01)
        .confidence_level(0.99)
        //.noise_threshold(0.01)
        //sampling_mode(SamplingMode::Auto) // intended for long-running benchmarks.
        //.nresamples(4000)
        //.measurement_time(std::time::Duration::from_secs(10))
        //.sample_size(100)
        //.warm_up_time(Duration::from_secs(5))
    ;

    for i in inputs {
        group.bench_function(BenchmarkId::new("TrustDidWeb_resolve", i), |b| {
            b.iter(|| {
                let did_log_raw_filepath = format!{"test_data/generated_by_didtoolbox_java/v{:03}_did.jsonl", i};
                let did_url =
                    "did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085";

                let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();

                if let Some(err) = TrustDidWeb::resolve(black_box(did_url.to_string()), black_box(did_log_raw)).err() {
                    panic!("{}", err.to_string());
                }
            })
        });
    }
    group.finish();
}

pub fn criterion_benchmark_did_tdw_jsonschema(c: &mut Criterion) {
    let inputs = [5, 10, 50, 100, 200, 300, 400];

    let mut group = c.benchmark_group("did_tdw_jsonschema");
    group
        .significance_level(0.01)
        .confidence_level(0.99)
        //.noise_threshold(0.01)
        //sampling_mode(SamplingMode::Auto) // intended for long-running benchmarks.
        //.nresamples(4000)
        //.measurement_time(std::time::Duration::from_secs(10))
        //.sample_size(100)
        //.warm_up_time(Duration::from_secs(5))
    ;

    let sch: &dyn DidLogEntryJsonSchema = &TrustDidWebDidLogEntryJsonSchema::V03EidConform;
    let validator = DidLogEntryValidator::from(sch);

    let function_name_base = "DidLogEntryValidator_validate";

    for i in inputs {
        group.bench_function(
            BenchmarkId::new(format!("{} {}", function_name_base, "(sequential)"), i),
            |b| {
                b.iter(|| {
                    let did_log_raw_filepath =
                        format! {"test_data/generated_by_didtoolbox_java/v{:03}_did.jsonl", i};

                    let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();

                    if let Some(err) = did_log_raw
                        .lines()
                        //.find_map(|line| validator.validate(black_box(String::from(line))).err()) {
                        .find_map(|line| validator.validate_str(black_box(line)).err())
                    {
                        panic!("{}", err.to_string());
                    }
                })
            },
        );

        group.bench_function(
            BenchmarkId::new(
                format!(
                    "{} (parallel, using {} of {} core(s))",
                    function_name_base,
                    rayon::current_num_threads(),
                    // On MacOS, this should match the result of running `sysctl -a machdep.cpu` command
                    std::thread::available_parallelism().unwrap().get(),
                ),
                i,
            ),
            |b| {
                b.iter(|| {
                    let did_log_raw_filepath =
                        format! {"test_data/generated_by_didtoolbox_java/v{:03}_did.jsonl", i};

                    let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();

                    if let Some(err) = did_log_raw
                        .par_lines() // engage a parallel iterator (thanks to 'use rayon::prelude::*;' import)
                        // Once a non-None value is produced from the map operation,
                        // it will attempt to stop processing the rest of the items in the iterator as soon as possible.
                        //.find_map_any(|line| validator.validate(black_box(String::from(line))).err()) {
                        .find_map_any(|line| validator.validate_str(black_box(line)).err())
                    {
                        panic!("{}", err.to_string());
                    }
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    criterion_benchmark_setup,
    criterion_benchmark_did_tdw,
    criterion_benchmark_did_tdw_jsonschema
);
criterion_main!(benches);
