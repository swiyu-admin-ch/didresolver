# Foreign language (UniFFI) test cases

The [`uniffi::build_foreign_language_testcases`](https://docs.rs/uniffi/latest/uniffi/macro.build_foreign_language_testcases.html)
macro is introduced for the sake of being able to build testcases for a component's generated bindings.
This macro provides some plumbing to write automated tests for the generated foreign language bindings of a component.

As a component author, you can write script files in the target foreign language(s) that exercise you component API,
and then call this macro to produce a cargo test testcase from each one. The generated code will execute your script file
with appropriate configuration and environment to let it load the component bindings, and will pass iff the script exits
successfully.

To use it, invoke the macro with the name of a fixture/example crate as the first argument, then one or more file paths
relative to the crate root directory. It will produce one `#[test]` function per file, in a manner designed to play nicely
with cargo test and its test filtering options.

As advised by [uniffi-rs examples](https://github.com/mozilla/uniffi-rs/tree/main/examples), so you will also need:

* The [Kotlin command-line tools](https://kotlinlang.org/docs/tutorials/command-line.html), particularly `kotlinc`.
  Furthermore, the [Java Native Access](https://github.com/java-native-access/jna#download) JAR downloaded and its path
  added to your `$CLASSPATH` environment variable e.g.:
  ```shell
  jna_ver=5.17.0 # update accordingly
  jna_jar_url=https://repo1.maven.org/maven2/net/java/dev/jna/jna/$jna_ver/jna-$jna_ver.jar
  
  wget -q $jna_jar_url -P target
  export CLASSPATH=$(pwd)/target/jna-$jna_ver.jar
  ``` 
* Python 3
* The [Swift command-line tools](https://swift.org/download/), particularly `swift`, `swiftc` and
  the `Foundation` package.

With all that in place, just try running `cargo test` and it will spin-up each of the foreign-language testcases against the compiled Rust code,
confirming whether everything is working as intended.

This will also generate the foreign-language bindings, which load the compiled Rust code
and use the C FFI generated above to interact with it.

For Kotlin, the generated code resides in: `./target/tmp/<REPO_NAME>-<SOME_UNIQUE_HASH>/**/*.kt`.
The package structure is defined implicitly via the `package_name` property set in [`uniffi.toml`](../uniffi.toml).
For instance, for `package_name = "ch.admin.eid.didresolver"`:
```
$ tree target/tmp/didresolver-*  

target/tmp/didresolver-3c6c6c90f26331aa
├── ch
│    └── admin
│        └── eid
│            ├── did_sidekicks
│            │   └── did_sidekicks.kt
│            ├── did_webvh
│            │   └── did_webvh.kt
│            ├── didresolver
│            │   └── did.kt
│            └── didtoolbox
│                └── did_tdw.kt
├── didresolver.jar
└── libdidresolver.dylib
```
