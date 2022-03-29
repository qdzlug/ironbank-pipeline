# Cosign Signatures

The Iron Bank pipeline is now performing cosign signatures on all images pushed to the `ironbank` project within Registry1.

Please see the adjacent pem file, `cosign-certificate.pem` for the public cert used to verify these signatures.

The CA bundle cert can be used to validate the `cosign-certificate.pem` file's authenticity.
