# Legacy DID logs

This directory features DID logs created by various legacy versions of DID Toolbox.

⚠️ Needless to say, these DID logs are intended for testing purposes only.
The idea behind such unit tests is to ensure that **the latest DID Resolver is also compatible with all the legacy DID Toolbox versions,
hence it is able to resolve DID logs created by any legacy version of the DID Toolbox**.

All the `*.jsonl` files available here can be generated using the following script:

```bash
# PREREQ Java is already installed
# An HTTP(S) DID URL (to did.jsonl) to create TDW DID log for
DID_URL=https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085

# v1.0.0 (deprecated), features no 'update' command
wget -q https://github.com/e-id-admin/didtoolbox-java/releases/download/1.0.0/didtoolbox.jar -O didtoolbox-1.0.0.jar
# cleanup (as the version did not feature -f option)
rm -fr .didtoolbox
# DID log creation
java -jar didtoolbox-1.0.0.jar create -u $DID_URL    > did-1.0.0.jsonl

# CAUTION The v1.1.0 must be downloaded manually from https://github.com/swiyu-admin-ch/didtoolbox-java/packages/2420331?version=1.1.0
# cleanup (as the version did not feature -f option)
rm -fr .didtoolbox
# DID log creation
java -jar didtoolbox-1.1.0.jar create -u $DID_URL    > did-1.1.0.jsonl

# v1.2.0
wget -q https://github.com/swiyu-admin-ch/didtoolbox-java/releases/download/1.2.0/didtoolbox.jar -O didtoolbox-1.2.0.jar
# DID log creation
java -jar didtoolbox-1.2.0.jar create -u $DID_URL -f > did-1.2.0.jsonl

# v1.3.0
wget -q https://github.com/swiyu-admin-ch/didtoolbox-java/releases/download/1.3.0/didtoolbox.jar -O didtoolbox-1.3.0.jar
# DID log creation
java -jar didtoolbox-1.3.0.jar create -u $DID_URL -f > did-1.3.0.jsonl

# a handy shell function for all didtoolbox versions available on Maven Central (Repository) 
create_did_log_using_didtoolbox_ver () {
	local mvn_base_url=$1; local ver=$2; local url=$3
	# download the exact version
	wget -q $mvn_base_url/$ver/didtoolbox-$ver-jar-with-dependencies.jar -O didtoolbox-$ver.jar
	# DID log creation
	java -jar didtoolbox-$ver.jar create -u $url -m did:tdw:0.3 -f > did-$ver.jsonl
}

# All groupId=io.github.swiyu-admin-ch versions available on Maven Central Repository.
# Further versions will be added here as soon as they get released
for ver in 1.3.1 1.4.0 1.4.1 1.4.2 1.5.0 1.6.0 1.7.0; do \
    create_did_log_using_didtoolbox_ver https://repo1.maven.org/maven2/io/github/swiyu-admin-ch/didtoolbox $ver $DID_URL
done

# All groupId=ch.admin.swiyu versions available on Maven Central Repository.
# Further versions will be added here as soon as they get released
for ver in 1.8.0 1.9.0 1.9.1 2.0.0; do \
    create_did_log_using_didtoolbox_ver https://repo1.maven.org/maven2/ch/admin/swiyu/didtoolbox $ver $DID_URL
done
```

## The DID Toolbox as dependent

As expected, the [DID Resolver (Kotlin)](https://github.com/swiyu-admin-ch/didresolver-kotlin) is also used by the [DID Toolbox](https://github.com/swiyu-admin-ch/didtoolbox-java) itself.
Here is a short list of all the DID Resolver versions used by the DID Toolbox:

|                                  didresolver<br>version                                   | Date<br>published | Used in<br>didtoolbox<br>version |                                       All other<br>dependents                                       |
|:-----------------------------------------------------------------------------------------:|:-----------------:|:--------------------------------:|:---------------------------------------------------------------------------------------------------:|
|      [2.7.0](https://central.sonatype.com/artifact/ch.admin.swiyu/didresolver/2.7.0)      |    2026-03-25     |          2.0.0<br>1.9.1          |      [link](https://central.sonatype.com/artifact/ch.admin.swiyu/didresolver/2.7.0/dependents)      |
| [2.6.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.6.0) |    2026-01-13     |          1.9.0<br>1.8.0          | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.6.0/dependents) |
| [2.5.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.5.0) |    2026-01-07     |                -                 | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.5.0/dependents) |
| [2.4.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.4.0) |    2025-11-24     |                -                 | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.4.0/dependents) |
| [2.3.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.3.0) |    2025-10-24     |              1.7.0               | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.3.0/dependents) |
| [2.2.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.2.0) |    2025-08-30     |              1.6.0               | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.2.0/dependents) |
| [2.1.3](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.3) |    2025-08-02     |          1.5.0<br>1.4.2          | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.3/dependents) |
| [2.1.2](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.2) |    2025-06-23     |              1.4.1               | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.2/dependents) |
| [2.1.1](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.1) |    2025-06-10     |              1.4.0               | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.1/dependents) |
| [2.1.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.0) |    2025-06-04     |                -                 | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.0/dependents) |
| [2.0.1](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.0.1) |    2025-05-07     |              1.3.1               | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.0.1/dependents) |

