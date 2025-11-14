# Legacy DID logs

This directory feature DID logs created by various legacy versions od DID Toolbox.

⚠️ Needless to say, these DID logs are intended for testing purposes only.

All the `*.jsonl` files available here can be generated using the following script:

```bash
# PREREQ Java is already installed
# An HTTP(S) DID URL (to did.jsonl) to create WEBVH DID log for
DID_URL=https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085

# a handy shell function for all didtoolbox versions available on Maven Central (Repository) 
create_did_log_using_didtoolbox_ver () {
	local ver=$1; local url=$2
	# download the exact version
	wget -q https://repo1.maven.org/maven2/io/github/swiyu-admin-ch/didtoolbox/$ver/didtoolbox-$ver-jar-with-dependencies.jar -O didtoolbox-$ver.jar
	
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
# Further versions will be added here as soon as they get released
for ver in 1.6.0 1.7.0; do \
	create_did_log_using_didtoolbox_ver $ver $DID_URL
done
```