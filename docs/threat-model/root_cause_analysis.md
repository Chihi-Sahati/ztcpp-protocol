# NHP-SBA Formal Verification Deadlock Report

**Status**: ROOT CAUSE CLASSIFICATION PHASE
**Date**: 2026-06-15

---

## 1. ROOT CAUSE CLASSIFICATION

**Classification: A. Specification Error (Invariant is mathematically incorrect)**

The transition guard successfully and atomically validated the SAT payload at entry. The failure was caused by the continuous mathematical definition of the invariant `SATValidityInvariant`, which incorrectly demanded that the temporal bounds of the SAT token (`clock <= sat.exp`) remain valid continuously into the future, forever, as long as `state == "ESTABLISHED"`. This contradicts the rule that SAT is a short-lived token evaluated exactly once at the entry guard.

---

## 2. PROOF OF REAL COUNTEREXAMPLE

**Full State Trace**:
```tla
State 1: <Initial predicate>
/\ state = (a1 :> "LISTEN")
/\ clock = 0

State 2: <RequestSAT>
/\ sat_registry = {[iat |-> 0, exp |-> 1, agent |-> a1, active |-> TRUE]}
/\ clock = 0

State 3: <SendHandshake>
/\ network = {[agent |-> a1, nonce |-> 1, type |-> "KNK"]}
/\ clock = 0

State 4: <AtomicVerifyAndEvaluate(a1)>
/\ state = (a1 :> "ESTABLISHED")
/\ highest_nonce = (a1 :> 1)
/\ clock = 0

State 5: <Tick>
/\ state = (a1 :> "ESTABLISHED")
/\ clock = 1

State 6: <Tick>
/\ state = (a1 :> "ESTABLISHED")
/\ clock = 2
```

**Exact Transition Causing Violation**: `Tick` (State 5 -> State 6).
The invariant evaluated to FALSE precisely when `clock` advanced from 1 to 2, violating `clock <= sat.exp` (`2 <= 1`).

**Proof of Expiration**:
The SAT expired **AFTER** evaluation.
The `AtomicVerifyAndEvaluate` transition occurred completely atomically at `clock = 0`. At that exact transition, the token bounds were `iat=0, exp=1`. The guard evaluation `(sat.iat <= clock /\ clock <= sat.exp)` equated to `(0 <= 0 /\ 0 <= 1)` which is TRUE.
The token expiration occurred independently via environment `Tick` transitions exclusively AFTER the `ESTABLISHED` state was achieved. There was no mid-transition expiration.

---

## 3. ATOMICITY AUDIT

**Proof**: SAT Validity is checked **INSIDE transition (atomic)**.

In the `NHP-SBA_Deterministic_Model.tla`, the transition logic merges all stages:
```tla
AtomicVerifyAndEvaluate(a) ==
    ...
    /\ IF (m.nonce > highest_nonce[a]) 
          /\ (sat.iat <= clock /\ clock <= sat.exp)  \* <-- GUARD EVALUATED HERE
          /\ (score >= MinSafetyScore)
       THEN
          /\ state' = [state EXCEPT ![a] = "ESTABLISHED"]
```
Because TLA+ transitions execute completely instantaneously, it is mathematically impossible for the `clock` to tick between the SAT validity check and the `state' = "ESTABLISHED"` assignment. Therefore, the transition is definitively atomic and the model structure is valid. 

Because it is atomic, the continuous invariant `SATValidityInvariant` fails strictly because it asserts properties about post-transition states that violate the rules of short-lived tokens.

---

## 4. FINAL REQUIRED DECISION OUTPUT

SPECIFICATION IS INCONSISTENT — REDEFINE SEMANTICS
