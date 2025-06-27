images
---

Install both [cargo-modules](https://github.com/regexident/cargo-modules) and [graphviz](https://graphviz.org/download/), and then run:
```shell
cargo-modules dependencies --splines ortho --no-externs --no-modules --lib | dot -Tpng > images/dependencies.png
```
