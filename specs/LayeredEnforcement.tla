---- MODULE LayeredEnforcement ----
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
  FsReadIn, FsReadOut, FsWriteIn, FsWriteOut,
  ExecAllowed, ExecDenied, ConnectAllowed, ConnectDenied,
  PolicyAllowed, MaxQueue, MaxLog, KernelInitiallyOn, AllowKernelUnload

VARIABLES shim, shimEvaded, landlock, landlockEver, bpf, queue, log

Ops == {FsReadIn, FsReadOut, FsWriteIn, FsWriteOut, ExecAllowed, ExecDenied, ConnectAllowed, ConnectDenied}

Class(op) ==
  IF op \in {FsReadIn, FsReadOut, FsWriteIn, FsWriteOut} THEN "fs"
  ELSE IF op \in {ExecAllowed, ExecDenied} THEN "exec"
  ELSE "net"

PolicyAllows(op) == op \in PolicyAllowed
KernelCovers(op) == bpf \/ (landlock /\ Class(op) \in {"fs", "exec"})
KernelDenies(op) == KernelCovers(op) /\ ~PolicyAllows(op)
ShimDenies(op) == shim /\ ~shimEvaded /\ ~PolicyAllows(op)

vars == <<shim, shimEvaded, landlock, landlockEver, bpf, queue, log>>

Init ==
  /\ shim = TRUE
  /\ shimEvaded = FALSE
  /\ landlock = KernelInitiallyOn
  /\ landlockEver = KernelInitiallyOn
  /\ bpf = KernelInitiallyOn
  /\ queue = <<>>
  /\ log = <<>>

Enqueue ==
  /\ Len(queue) < MaxQueue
  /\ \E op \in Ops: queue' = Append(queue, op)
  /\ UNCHANGED <<shim, shimEvaded, landlock, landlockEver, bpf, log>>

ProcessAllowed ==
  /\ Len(queue) > 0
  /\ Len(log) < MaxLog
  /\ LET op == Head(queue) IN
       /\ PolicyAllows(op)
       /\ log' = Append(log, [op |-> op, class |-> Class(op), kernel |-> KernelCovers(op)])
  /\ queue' = Tail(queue)
  /\ UNCHANGED <<shim, shimEvaded, landlock, landlockEver, bpf>>

ProcessDeniedBlocked ==
  /\ Len(queue) > 0
  /\ LET op == Head(queue) IN
       /\ ~PolicyAllows(op)
       /\ KernelDenies(op) \/ ShimDenies(op)
  /\ queue' = Tail(queue)
  /\ UNCHANGED <<shim, shimEvaded, landlock, landlockEver, bpf, log>>

ProcessDeniedEffect ==
  /\ Len(queue) > 0
  /\ Len(log) < MaxLog
  /\ LET op == Head(queue) IN
       /\ ~PolicyAllows(op)
       /\ ~KernelDenies(op)
       /\ ~ShimDenies(op)
       /\ log' = Append(log, [op |-> op, class |-> Class(op), kernel |-> KernelCovers(op)])
  /\ queue' = Tail(queue)
  /\ UNCHANGED <<shim, shimEvaded, landlock, landlockEver, bpf>>

EvadeShim ==
  /\ shim
  /\ shimEvaded' = TRUE
  /\ UNCHANGED <<shim, landlock, landlockEver, bpf, queue, log>>

ExecResetsShim ==
  /\ shim
  /\ \E i \in 1..Len(queue): Class(queue[i]) = "exec"
  /\ shim' = FALSE
  /\ shimEvaded' = FALSE
  /\ UNCHANGED <<landlock, landlockEver, bpf, queue, log>>

ReloadShim ==
  /\ ~shim
  /\ shim' = TRUE
  /\ shimEvaded' = FALSE
  /\ UNCHANGED <<landlock, landlockEver, bpf, queue, log>>

ApplyLandlock ==
  /\ ~landlock
  /\ landlock' = TRUE
  /\ landlockEver' = TRUE
  /\ UNCHANGED <<shim, shimEvaded, bpf, queue, log>>

LoadBpf ==
  /\ ~bpf
  /\ bpf' = TRUE
  /\ UNCHANGED <<shim, shimEvaded, landlock, landlockEver, queue, log>>

UnloadBpf ==
  /\ AllowKernelUnload
  /\ bpf
  /\ bpf' = FALSE
  /\ UNCHANGED <<shim, shimEvaded, landlock, landlockEver, queue, log>>

Next ==
  \/ Enqueue
  \/ ProcessAllowed
  \/ ProcessDeniedBlocked
  \/ ProcessDeniedEffect
  \/ EvadeShim
  \/ ExecResetsShim
  \/ ReloadShim
  \/ ApplyLandlock
  \/ LoadBpf
  \/ UnloadBpf

TypeOK ==
  /\ shim \in BOOLEAN
  /\ shimEvaded \in BOOLEAN
  /\ landlock \in BOOLEAN
  /\ landlockEver \in BOOLEAN
  /\ bpf \in BOOLEAN
  /\ queue \in Seq(Ops)
  /\ Len(queue) <= MaxQueue
  /\ Len(log) <= MaxLog
  /\ log \in Seq([op: Ops, class: {"fs", "exec", "net"}, kernel: BOOLEAN])

NoDeniedEffectWhileKernelCovers ==
  \A i \in 1..Len(log):
    LET e == log[i] IN e.kernel => PolicyAllows(e.op)

NoDeniedEffect ==
  \A i \in 1..Len(log): PolicyAllows(log[i].op)

LandlockIrreversible == landlockEver => landlock

====
