# Threat Model

## In scope

* Prompt-injected agents attempting file reads/writes outside their workspace.
* Tool hijacking through non-allowlisted executables.
* Network exfiltration to non-allowlisted destinations.
* Stale, forged, expired, or revoked X.509 SPIFFE Verifiable Identity Documents.

## Out of scope

* Malicious kernel, root, or container runtime.
* Native-code bypass of Python audit hooks.
* Berkeley Packet Filter Linux Security Module runtime evaluation on kernels without that module enabled.

## Boundary statement

Landlock and the Berkeley Packet Filter Linux Security Module are kernel-enforced boundaries. Python audit hooks are cooperative guards only.
