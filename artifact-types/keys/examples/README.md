# Keys and Certificates examples

Runnable examples for [Keys and Certificates](../quickstart.md). No key or certificate is in this folder. You give
your own public files, and the script makes the signing key at run time. [`.gitignore`](.gitignore) keeps key files
out of git.

| File | What it shows |
| --- | --- |
| [`push-and-fingerprint.sh`](push-and-fingerprint.sh) | Print the local fingerprints (offline), make a signing key (first run only), push an SSH public key and a PEM certificate bundle, and show the entries that Prego recorded. |

```sh
export PREGO_TENANT=acme KEYS_NAMESPACE=release-keys
prego login --publish --namespace release-keys
sh artifact-types/keys/examples/push-and-fingerprint.sh ~/.ssh/deploy_ed25519.pub ./ca-bundle.pem
```

Give the public key file (`.pub`), never the private key file. If you give a private key by mistake, `prego` stops
before the upload and sends nothing:

```text
Keys and Certificates holds public keys and certificates only. Entry 0 holds a private key (OpenSSH private key). Upload the public key (`ssh-keygen -y -f <key>`) instead.
```
