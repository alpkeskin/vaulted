# Security policy

## Reporting a vulnerability

Please report privately, not in a public issue.

Use GitHub's [private vulnerability
reporting](https://github.com/alpkeskin/vaulted/security/advisories/new), or
email the maintainers.

Useful in a report: the version or commit, what you can do that you should not
be able to, and a reproduction if you have one. A proof-of-concept is welcome
but not required — a clear description of the flaw is worth more than working
exploit code.

You can expect an acknowledgement within a few days and an assessment within two
weeks. If a fix is needed, we will agree a disclosure date with you, and credit
you unless you would rather we did not.

## Scope

In scope, and taken seriously:

- Anything that recovers plaintext without the key
- Forging a ciphertext that authenticates
- Nonce reuse, or any weakening of nonce generation
- Plaintext or key material leaking into an error, `Debug` output, or a log
- A panic reachable from parsing attacker-controlled input
- Blind index behaviour that leaks more than equality and frequency
- Timing differences that distinguish decryption failure modes
- Key material surviving in memory past its intended lifetime in a way the code
  claims it does not

Out of scope:

- Attacks assuming the attacker already has the keys or code execution in the
  application process — see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- The equality and frequency leakage of blind indexes, which is documented and
  inherent to the design
- Ciphertext length leakage, likewise documented
- Weaknesses in AES-GCM, XChaCha20-Poly1305 or HMAC-SHA256 themselves; report
  those to the RustCrypto project, though we would like to know
- Insecure configurations the library warns about, such as a world-readable
  keyfile loaded with the permission check explicitly disabled

## Supported versions

Pre-1.0: only the latest release is supported. Once 1.0 ships, the latest minor
of the current major will be.

## Design commitments

These are properties of the project, not aspirations. A change that breaks one
is a bug:

1. No custom cryptography. Established primitives, used as documented.
2. Authenticated encryption only. No unauthenticated mode exists.
3. A fresh random nonce per operation, from the OS CSPRNG. No API accepts a
   caller-supplied nonce, and randomness failure aborts the operation.
4. Encryption keys and blind index keys are independent material.
5. Keys never go in the database, and never in errors, logs or `Debug` output.
6. Plaintext never appears in an error message.
7. All decryption failures are indistinguishable to the caller.
8. Ciphertext is versioned, so migration never requires a flag day.
9. All parsing treats its input as hostile.
10. Secure defaults; insecure configurations must be explicit.

## Audit status

Vaulted has **not** had an external security audit. The test suite covers
tampering, cross-field reuse, wrong keys, malformed input and rotation, and the
parsers are fuzzed — but that is not the same thing, and this section will be
updated when it changes.
