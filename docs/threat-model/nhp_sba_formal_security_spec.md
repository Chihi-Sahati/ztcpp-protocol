# NHP-SBA Formal Security & Verification Specification

**Status**: Protocol Freeze Phase
**Date**: 2026-06-15

This document serves as the mandatory formalization of the Zero Trust Control and Policy Protocol (NHP-SBA) before advancing to implementation scaffolding. It defines the strict cryptographic boundaries, state-machine invariants, and mathematical constraints necessary to validate protocol correctness.

---

## 1. Full Threat Model

The NHP-SBA architecture assumes an untrusted underlying transport network (e.g., public internet, exposed 5G fronthaul) and operates under a strict "Assume Breach" zero-trust paradigm.

### 1.1 Replay Attacks
- **Threat**: An adversary captures a valid `NHPHandshake` request and replays it to exhaust gateway resources or trigger unauthorized actions.
- **Formal Mitigation**: The payload MUST include a monotonically increasing `nonce` or a high-precision `timestamp`. The edge gateway MUST reject any `nonce` $\le$ the highest observed `nonce` for a given `AgentID`. The state for nonce tracking MUST be $O(1)$ per agent, stored in a fast lookup table (e.g., Redis or in-memory LRU cache).
- **Invariant**: $Nonce_{current} > Nonce_{previous}$.

### 1.2 Impersonation Attacks
- **Threat**: An unauthorized entity attempts to forge a valid SAT (System Authentication Token) or masquerade as a valid autonomous agent.
- **Formal Mitigation**: Every handshake MUST be signed using Ed25519 (JWS format). The public key of the `AgentID` MUST be pre-registered via the NHP-NRS control plane. The signature is computed over the concatenated `(SAT_Hash || Nonce || IntentID)`.
- **Invariant**: $Verify_{Ed25519}(PubKey_{Agent}, Signature, Payload) == True$.

### 1.3 Downgrade Attacks
- **Threat**: An active Man-in-the-Middle (MitM) intercepts the handshake and attempts to negotiate a weaker cipher suite.
- **Formal Mitigation**: NHP-SBA enforces a **Zero-Negotiation Policy**. The cryptographic suite (Noise IK pattern, Ed25519, ChaCha20-Poly1305) is strictly hardcoded. Any packet requesting a different suite is dropped at the edge.
- **Invariant**: $CipherSuite \in \{ \text{Strictly\_Approved\_Set} \}$.

### 1.4 SAT Abuse & Lateral Movement
- **Threat**: A compromised internal agent uses a valid SAT to access unauthorized 3GPP Service Based Architecture (SBA) nodes.
- **Formal Mitigation**: SAT tokens are short-lived ($\le$ 60 seconds) and strictly bound to a specific `Audience` (Target NF) and `Intent`. The MAMA gateway acts as a Policy Enforcement Point (PEP) to ensure lateral movement is cryptographically impossible without a new, intent-specific SAT.
- **Invariant**: $SAT_{exp} > Time_{now}$ AND $SAT_{audience} == Target_{NF}$ AND $SAT_{intent} == Requested_{Intent}$.

---

## 2. Formal Verification Model: NHP State Machine

The Node Handshake Protocol (NHP) operates as a strict **Fail-Closed 5-State Machine**. True zero-state memory allocation requires that state transitions only occur *after* cryptographically verifying the input.

To provide independent machine-checkable proofs of these transitions, a complete **TLA+ Specification** has been authored. 

**Formal Verification Artifact**: [nhp_sba_formal_model.tla](file:///c:/Users/husse/Documents/Dr%20Houda/%D9%85%D8%AC%D9%84%D8%AF%20%D8%AC%D8%AF%D9%8A%D8%AF/Code/nhp_sba/docs/threat-model/nhp_sba_formal_model.tla)

This TLA+ model mathematically proves the following properties via TLC model checking:
1. **Safety (Replay Immunity)**: No two identical messages can ever result in an `ESTABLISHED` state.
2. **Safety (Temporal Bounds)**: `EVALUATE_MAMA` and `ESTABLISHED` states cannot be reached if $Clock > SAT_{exp}$.
3. **Liveness (Termination)**: Any state entering the MAMA evaluation engine is guaranteed to resolve (`~>`) to either `ESTABLISHED` or `LISTEN`.

### State Transitions:
1. **State 0 (LISTEN_EDGE)**: eBPF/XDP listener. Zero TCP/IP socket memory allocated.
2. **State 1 (PARSE_SIG)**: Extracts Ed25519 signature and Nonce.
   - *Transition to State 2* IF $Verify == True$ AND $Nonce > previous$.
   - *Else* DROP (Return to State 0).
3. **State 2 (VERIFY_SAT)**: Validates the token's temporal bounds and audience.
   - *Transition to State 3* IF Valid.
   - *Else* DROP (Return to State 0).
4. **State 3 (EVALUATE_MAMA)**: The deterministic policy engine evaluates the intent.
   - *Transition to State 4* IF $Score_{safety} \ge Min\_Threshold$.
   - *Else* REJECT (HTTP 403 / Return to State 0).
5. **State 4 (SESSION_ESTABLISHED)**: A secure micro-tunnel (ChaCha20-Poly1305) is established to the target NF.

**Formal Correctness Requirement**: The memory footprint of any connection attempt in State 1 MUST be strictly bounded and immediately freed if the transition to State 2 fails.

---

## 3. MAMA Safety Gate Invariants

The Micro-tunneling and Autonomous Mediation Architecture (MAMA) enforces mathematical constraints on the operational network.

### 3.1 The Safety Score Equation
$$ Score_{safety} = (w_1 \times (1 - EDNS)) + (w_2 \times CEI) $$

- **EDNS** (Expected Demand Not Served): A normalized metric $[0, 1]$ representing core network saturation.
- **CEI** (Capability Effectiveness Index): A normalized metric $[0, 1]$ representing the operational value of the agent's intent.
- **Weights**: $w_1 + w_2 = 1.0$.

### 3.2 Formal Constraints
1. **Minimum Safety Threshold**: $\forall \text{ intents}, Score_{safety} \ge \tau_{min}$ (where $\tau_{min} \approx 0.85$).
2. **Saturation Circuit Breaker**: If $EDNS \to 1$, then $Score_{safety} \approx w_2 \times CEI$. Unless the intent is highly critical ($CEI \approx 1.0$ and $w_2$ is high), the score will fall below $\tau_{min}$, triggering an automatic reject.
3. **Funding Ratio Invariant**: The required SLA penalty exposure must not exceed the operational funding pool: $Cost(Intent) \le Funding_{Available}$.

---

## 4. Serialization Strategy Evaluation Criteria

The decision between Protobuf and FlatBuffers is deferred until the following tradeoffs are evaluated:

1. **Cryptographic Binding Constraints**:
   - The signature must cover the exact byte layout of the payload to prevent parsing ambiguity attacks.
   - FlatBuffers guarantees a deterministic memory layout, which favors direct byte-level hashing. Protobuf requires canonical serialization before hashing.
2. **Auditability vs. Performance**:
   - Protobuf is highly audited and supported across Python/Rust/C++ ecosystems but requires allocation during deserialization.
   - FlatBuffers supports zero-copy deserialization (aligning perfectly with NHP-SBA's zero-state requirement) but has a steeper audit curve for security vulnerabilities (e.g., bounds checking on malformed offsets).

---

## 5. Trust Zones & Language Selection Drivers

Language selection MUST align with the security boundary defined by the Trust Zones.

### 5.1 Trust Zone A: The Absolute Edge (Untrusted)
- **Component**: NHP Edge Gateway (eBPF/XDP Listener, Signature Verifier).
- **Driver**: Absolute memory safety, zero garbage collection, predictable latency.
- **Selection**: MUST be **Rust** or **C** (for eBPF).

### 5.2 Trust Zone B: Policy Enforcement Point (PEP)
- **Component**: MAMA Safety Gates, SAT Validator.
- **Driver**: High concurrency, type safety, integration with telemetry.
- **Selection**: MUST be **Rust** for the daemon core.

### 5.3 Trust Zone C: Control Plane & Orchestration
- **Component**: NHP-NRS, Telemetry aggregators, ML Analytics.
- **Driver**: Ecosystem support (AI/ML), rapid iteration, complex routing logic.
- **Selection**: **Python** or **Go** is acceptable, provided they operate *behind* the NHP Gateway.

### 5.4 Trust Zone D: Autonomous Agents
- **Component**: Agent SDKs (Drones, SDR controllers).
- **Driver**: Portability across architectures (ARM, x86) and environments (GNU Radio, ROS).
- **Selection**: **Python**, **C++**, and **Rust** SDKs.
