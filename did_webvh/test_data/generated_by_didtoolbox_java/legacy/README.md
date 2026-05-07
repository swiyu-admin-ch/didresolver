# Legacy DID logs

This directory features DID logs created by various legacy versions of DID Toolbox.

⚠️ Needless to say, these DID logs are intended for testing purposes only.
The idea behind such unit tests is to ensure that **the latest DID Resolver is also compatible with all the legacy DID Toolbox versions,
hence it is able to resolve DID logs created by any legacy version of the DID Toolbox**.

All the `*.jsonl` files available here can be generated using the following script:

```bash
# PREREQ Java is already installed
# An HTTP(S) DID URL (to did.jsonl) to create WEBVH DID log for
DID_URL=https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085

# a handy shell function for all didtoolbox versions available on Maven Central (Repository) 
create_did_log_using_didtoolbox_ver () {
	local mvn_base_url=$1; local ver=$2; local url=$3
	# download the exact version
	wget -q $mvn_base_url/$ver/didtoolbox-$ver-jar-with-dependencies.jar -O didtoolbox-$ver.jar
	
	rm -fr .didtoolbox* &>/dev/null
	
	# Step 1 - Generate new DID and redirect stdout to v01_did.jsonl file (contains the created DID log)
	java -jar didtoolbox-$ver.jar create -u $url -m did:webvh:1.0 -f > v01_did.jsonl
	    
	# Step 2 - Rename the generated .didtoobox folder to make sure the initially generated key material remains accessible
	mv .didtoolbox .didtoolbox_keys_v01
	
	# Step 3 - To keep it simple, create a new dummy DID so that we get a new set of key material (we're interested in the assertion key for the sake of this example).
	# No stdout redirect required, since we're only aiming for the key material that will be generated in the .didtoolbox directory.
	java -jar didtoolbox-$ver.jar create -u https://example.com -m did:webvh:1.0 -f &> /dev/null
	
	# Step 4 - Update the DID from step 1, so that the assert key is rotated to a new one while the previous one is removed. We'll keep the authentication key.
	# Redirect stdout to v02_did.jsonl file (contains the updated DID log, now with two versions)
	java -jar didtoolbox-$ver.jar update \
		-d v01_did.jsonl \
		-s .didtoolbox_keys_v01/id_ed25519 \
		-v .didtoolbox_keys_v01/id_ed25519.pub \
		-a assert-key-02,.didtoolbox/assert-key-01.pub \
		-t auth-key-01,.didtoolbox_keys_v01/assert-key-01.pub > did-$ver.jsonl
	
	rm didtoolbox-$ver.jar v0*_did.jsonl
}

# All versions available on Maven Central Repository that support creation of did:webvh:1.0 DID logs.
# Old groupId (io.github.swiyu-admin-ch) until 1.7.0.
# Further versions will be added here as soon as they get released
for ver in 1.6.0 1.7.0; do \
	create_did_log_using_didtoolbox_ver https://repo1.maven.org/maven2/io/github/swiyu-admin-ch/didtoolbox $ver $DID_URL
done

# All versions available on Maven Central Repository that support creation of did:webvh:1.0 DID logs.
# New groupId (ch.admin.swiyu) since 1.8.0.
# Further versions will be added here as soon as they get released
for ver in 1.8.0 1.9.0 1.9.1 2.0.0; do \
	create_did_log_using_didtoolbox_ver https://repo1.maven.org/maven2/ch/admin/swiyu/didtoolbox $ver $DID_URL
done
```

## The DID Toolbox as dependent

As expected, the [DID Resolver (Kotlin)](https://github.com/swiyu-admin-ch/didresolver-kotlin) is also used by the [DID Toolbox](https://github.com/swiyu-admin-ch/didtoolbox-java) itself.
Here is a short list of all the DID Resolver versions used by the DID Toolbox:

|                                  DID Resolver<br>version                                  | Date<br>published | Used in<br>DID Toolbox<br>version |                                       All other<br>dependents                                       |
|:-----------------------------------------------------------------------------------------:|:-----------------:|:---------------------------------:|:---------------------------------------------------------------------------------------------------:|
|      [2.7.0](https://central.sonatype.com/artifact/ch.admin.swiyu/didresolver/2.7.0)      |    2026-03-25     |          2.0.0<br>1.9.1           |      [link](https://central.sonatype.com/artifact/ch.admin.swiyu/didresolver/2.7.0/dependents)      |
| [2.6.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.6.0) |    2026-01-13     |          1.9.0<br>1.8.0           | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.6.0/dependents) |
| [2.5.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.5.0) |    2026-01-07     |                 -                 | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.5.0/dependents) |
| [2.4.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.4.0) |    2025-11-24     |                 -                 | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.4.0/dependents) |
| [2.3.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.3.0) |    2025-10-24     |               1.7.0               | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.3.0/dependents) |
| [2.2.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.2.0) |    2025-08-30     |               1.6.0               | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.2.0/dependents) |
| [2.1.3](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.3) |    2025-08-02     |          1.5.0<br>1.4.2           | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.3/dependents) |
| [2.1.2](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.2) |    2025-06-23     |               1.4.1               | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.2/dependents) |
| [2.1.1](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.1) |    2025-06-10     |               1.4.0               | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.1/dependents) |
| [2.1.0](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.0) |    2025-06-04     |                 -                 | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.1.0/dependents) |
| [2.0.1](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.0.1) |    2025-05-07     |               1.3.1               | [link](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/didresolver/2.0.1/dependents) |

