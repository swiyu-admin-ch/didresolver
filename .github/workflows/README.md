# workflows

This configuration directory containing various YAML files describing GitHub Actions workflows,
as advised [here](https://docs.github.com/en/actions/get-started/understanding-github-actions#workflows):

_A workflow is a configurable automated process that will run one or more jobs.
Workflows are defined by a YAML file checked in to your repository and will run when triggered by an event in your repository,
or they can be triggered manually, or at a defined schedule._

This repo features the following workflows:

| Name                           | YAML                                                   | Description                       | Artifacts <br>(produced during runtime) |
|--------------------------------|--------------------------------------------------------|-----------------------------------|:---------------------------------------:|
| rust-clippy analyze            | [`rust-clippy.yml`](rust-clippy.yml)                   | Run rust-clippy analyzing         |                   :x:                   |
| Build library (Kotlin)         | [`build_kotlin.yml`](build_kotlin.yml)                 | Build Kotlin bindings             |           :white_check_mark:            |
| Build library (Kotlin-Android) | [`build_kotlin-android.yml`](build_kotlin-android.yml) | Build Kotlin bindings for Android |           :white_check_mark:            |
| Build library (Swift)          | [`build_swift.yml`](build_swift.yml)                   | Build Swift bindings              |           :white_check_mark:            |

The artifacts are generated for various OSs and CPU architectures. 
