# Public test-only TLS fixtures

The certificate and private key in this directory are intentionally public and are used only by the local test HTTPS server. They are not production credentials. Never deploy them.

The fixture covers localhost and 127.0.0.1. Tests explicitly trust the certificate in an isolated client context to verify a successful handshake, and also verify that the default client rejects it and that hostname verification remains enabled. System trust settings are never modified.
