# NHP-SBA True TLC Formal Verification Logs

**Date**: 2026-06-15
**Model**: `NHP-SBA_True_Formal_Model.tla`
**Status**: INVARIANT VIOLATION DETECTED (Counterexample Found)

---

## 1. TLC Execution Report & State Graph Statistics

TLC Model Checker (Version 2026.05.26) was executed natively using Java 21 OpenJDK. The state space was exhaustively searched up to the defined bounds.

**State Graph Statistics**:
- **States Generated**: 4,788
- **Distinct States Found**: 976
- **Depth of Complete State Graph Search**: 7
- **Search Type**: Breadth-first search (BFS)

### Counterexample Trace (`SATBound` Violation)

The model checker discovered a race condition where the `SATBound` invariant fails. The temporal bound of a token can expire *while* the gateway is processing the MAMA policy evaluation.

**Raw TLC Error Output**:
```text
Error: Invariant SATBound is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
... (Variables initialized)

State 2: <AgentRequestIntent>
/\ sat_registry = {[exp |-> 1, agent |-> a1, active |-> TRUE]}
/\ clock = 0

State 3: <SendHandshake>
/\ network = {[agent |-> a1, nonce |-> 1, type |-> "KNK"]}

State 4: <ReceiveKNK>
/\ state = (a1 :> "PARSE_SIG")

State 5: <ParseSig>
/\ state = (a1 :> "VERIFY_SAT")
/\ highest_nonce = (a1 :> 1)

State 6: <VerifySAT>
/\ state = (a1 :> "EVALUATE_MAMA")

State 7: <Tick>
/\ state = (a1 :> "EVALUATE_MAMA")
/\ clock = 1
```

**Analysis**: The transition `VerifySAT` succeeds because `sat.exp (1) > clock (0)`. The state becomes `EVALUATE_MAMA`. However, before `EvaluateMAMA` can execute, an environmental `Tick` occurs, advancing `clock` to 1. The invariant `sat.exp > clock` evaluates to `1 > 1` (FALSE) while the state is still `EVALUATE_MAMA`. This proves that without state-locking or monotonic timestamp pinning at the edge, a token can expire *during* evaluation, potentially allowing a session to establish post-expiration.

---

## 2. Adversarial Scenario Coverage List

The TLA+ Specification explicitly models the following attacker capabilities:
1. **Malicious Replay (`MaliciousReplay`)**: An attacker arbitrarily duplicates `KNK` payloads in transit.
2. **Server Compromise (`CompromiseServer`)**: The NHP-Server ignores signature validation and SAT expiration checks, bypassing edge authentication.
3. **Policy Engine Compromise (`CompromiseAC`)**: The MAMA gateway acts Byzantine, approving requests regardless of the `MinSafetyScore` (EDNS/CEI thresholds).
4. **Network Partition (`TogglePartition`)**: Temporary network splits preventing state transitions, simulating dropped packets.
5. **Undefined Behavior / Corruption (`UndefinedBehaviorHandling`)**: Arbitrary forced transition to `CORRUPTED` memory states.
6. **Concurrency Race Conditions**: Explored exhaustively via state interleaving (which successfully identified the `SATBound` violation).

---

## 3. Explicit Limitations Section (Mandatory)

The formal verification contains the following bounds:
- **Search Depth/Bounds**: `MaxNonce = 2`, `MaxTime = 3`, `Agents = {a1}`.
- **State Space Limitation Reasoning**: Unbounded clocks and nonces result in an infinitely large state space. To achieve termination and mathematically exhaustive BFS exploration in a finite timeframe, integer bounds are strictly constrained. Due to the symmetrical nature of the state machine, small constants (like `MaxTime=3`) are sufficient to expose edge-case concurrency interleavings (as proven by the discovered counterexample).
- **Coverage Percentage**: 100% of all possible interleavings *within* the defined bounded configuration.

---

## 4. Reproducibility Instructions

A third-party researcher can run this exact verification independently using the provided artifacts:

**Requirements**: Java 21+

**Steps**:
1. Download the TLA+ Tools jar:
   ```bash
   curl -LO https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
   ```
2. Verify that the files `NHP-SBA_True_Formal_Model.tla` and `NHP-SBA_True_Formal_Model.cfg` are in the same directory.
3. Run the TLC Model Checker with deadlock and invariant checking enabled:
   ```bash
   java -jar tla2tools.jar -config NHP-SBA_True_Formal_Model.cfg -deadlock NHP-SBA_True_Formal_Model.tla
   ```
4. The TLC engine will output the exact 7-step counterexample trace detailed above.
