# Product Requirements

Least-Privilege Agent Sandbox is a policy-enforcement point for AI-agent tool execution. It validates an
agent SPIFFE ID, compiles least-privilege policy into fast structures, and confines the tool process
using the strongest locally available backend.

Goals:

* Deny by default.
* Sub-3 ms p50 policy decisions.
* Real X.509-SVID validation with revocation-aware caching.
* Portable cooperative backend plus Linux kernel-enforced backend.
* Honest reporting when BPF LSM is unavailable.
