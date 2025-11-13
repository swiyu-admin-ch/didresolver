# Legacy DID logs

This directory feature DID logs created by various legacy versions od DID Toolbox.

⚠️ Needless to say, these DID logs are intended for testing purposes only.

All the *.jsonl` files available here can be generated using the following script:

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
	local ver=$1; local url=$2
	# download the exact version
	wget -q https://repo1.maven.org/maven2/io/github/swiyu-admin-ch/didtoolbox/$ver/didtoolbox-$ver-jar-with-dependencies.jar -O didtoolbox-$ver.jar
	# DID log creation
	java -jar didtoolbox-$ver.jar create -u $url -f > did-$ver.jsonl
}

# v1.3.1 (first version available on Maven Central Repository)
create_did_log_using_didtoolbox_ver 1.3.1 $DID_URL

# v1.4.0
create_did_log_using_didtoolbox_ver 1.4.0 $DID_URL

# v1.4.1
create_did_log_using_didtoolbox_ver 1.4.1 $DID_URL

# further versions will be added here as soon as they are released
```