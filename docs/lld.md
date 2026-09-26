# Low-Level Design

Policy YAML compiles to `SubjectPolicy` objects with normalized realpath prefix matchers, frozensets
for allowed tools/executables, and precompiled host glob matchers. `run_tool` validates the tool,
arguments, and executable before selecting BPF LSM, Landlock, or audit hooks.

Landlock is applied in a child just before `exec`. Filesystem rules come from read/write prefixes.
Network rules are used only on ABI >= 4, where Landlock can restrict TCP connect by port.

The BPF LSM prototype defines `file_open`, `bprm_check_security`, and `socket_connect` hooks using
per-cgroup policy maps. Runtime loading is intentionally skipped unless the kernel advertises BPF LSM.
