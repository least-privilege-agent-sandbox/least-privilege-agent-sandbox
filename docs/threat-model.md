# Threat Model

## In scope

* Prompt-injected agents attempting file reads/writes outside their workspace.
* Tool hijacking through non-allowlisted executables.
* Network exfiltration to non-allowlisted destinations.
* Stale, forged, expired, or revoked X.509-SVIDs.

## Out of scope

* Malicious kernel, root, or container runtime.
* Native-code bypass of Python audit hooks.
* BPF LSM runtime evaluation on kernels without BPF LSM enabled.

## Boundary statement

Landlock and BPF LSM are kernel-enforced boundaries. Python audit hooks are cooperative guards only.
