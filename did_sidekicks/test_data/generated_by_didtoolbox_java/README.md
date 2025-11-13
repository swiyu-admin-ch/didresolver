# DID logs for benchmarking

Among other artefacts, this directory also features several DID logs (`v*_did.jsonl`) intended for benchmarking purposes.
These were generated using [`didtoolbox`](https://github.com/swiyu-admin-ch/didtoolbox-java) available for download
[here](https://repo1.maven.org/maven2/io/github/swiyu-admin-ch/didtoolbox/). Here the relevant script:

```bash
# cleanup
rm -fr .didtoolbox
rm v*_did.jsonl
# optionally (replace <VERSION> with any of available versions)
# wget https://repo1.maven.org/maven2/io/github/swiyu-admin-ch/didtoolbox/<VERSION>/didtoolbox-<VERSION>-jar-with-dependencies.jar -O didtoolbox.jar
# initial log
java -jar didtoolbox.jar create -u https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085 > v001_did.jsonl
for i in {001..400}; do java -jar didtoolbox.jar update \
    -d v${i}_did.jsonl \
    -a my-assert-key-01,.didtoolbox/assert-key-01.pub \
    -t my-auth-key-01,.didtoolbox/auth-key-01.pub \
    -s .didtoolbox/id_ed25519 \
    -v .didtoolbox/id_ed25519.pub > v$(printf "%03d" $((i+1)))_did.jsonl
done
```

⚠️ Beware that running the script above may be rather time-consuming e.g. on Apple M3 (MacBook) Pro featuring
total 12 (6 performance and 6 efficiency) cores and 36 GB memory it may take over an hour to complete.
