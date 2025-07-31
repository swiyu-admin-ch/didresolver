# images

To be able to visualize/analyze the crate's internal dependencies, install both [cargo-modules](https://github.com/regexident/cargo-modules) and [graphviz](https://graphviz.org/download/) first, and then run:
```shell
cargo-modules dependencies --splines ortho --no-sysroot --lib | dot -Tpng > images/dependencies.png

# Feel free to try out other available graph layout algorithms (e.g. none, dot, neato, twopi, circo, fdp, sfdp) [default: neato], e.g.:
# cargo-modules dependencies --splines ortho --no-sysroot --layout neato --lib | dot -Tpng > images/dependencies-neato.png
```
