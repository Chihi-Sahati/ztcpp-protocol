# ZTCPP Reference Architecture & Implementation Plan

## PHASE 1 — REPOSITORY AUDIT

### Strengths
1. **Mathematical Foundation**: Strong conceptual backing with deterministic policy engines (MAMA Safety Gates) and rigorous mathematical modeling.
2. **Security Posture**: Implementation of a strict "Authenticated-before-Connect" (AbC) paradigm and Ed25519 JWS cryptography effectively eliminates state-exhaustion attacks.
3. **Simulation Maturity**: Existing `agent_simulator.py` and `performance_evaluator.py` provide empirical validation of sub-2ms latency.
4. **Modern Primitives**: Use of modern frameworks and languages (Rust for `nhp_ac`, Python for analytical/simulation components).

### Weaknesses
1. **Fragmented Architecture**: The repository currently blends academic simulation scripts with partial protocol implementations.
2. **Missing Low-Level System Bindings**: Lack of robust networking layers (e.g., eBPF/XDP) required to achieve true zero-state edge drops in a production kernel.
3. **Hardcoded Dependencies**: Simulations bypass standard network serialization (e.g., protobuf, flatbuffers), heavily relying on in-memory object passing.

### Missing Modules
1. **`agentdns/`**: A fully functional Intent Resolution daemon routing out-of-band requests.
2. **`sat/`**: A standalone System Authentication Token lifecycle manager.
3. **`sba/`**: The actual 3GPP Service Based Architecture proxy/sidecar for mediating 5G Core Network Functions (NFs).
4. **`experiments/`**: Hardware Abstraction Layers (HAL) bridging the protocol with USRP and TMYTEK SDR platforms.

### Technical Debt
1. Migration from analytical script architectures to a scalable microservices/daemon-based architecture.
2. Unifying the polyglot codebase (Rust, Python) under a single FFI or gRPC communication standard.

---

## PHASE 2 — TARGET ARCHITECTURE

The repository will be structured to support a production-grade, modular orchestration of the ZTCPP paradigm.

### Directory Tree

```text
ztcpp/
├── core/               # Shared protocol buffers, flatbuffers, and normative data structures
├── nhp/                # Node Handshake Protocol daemon (AbC Edge Gateway)
├── agentdns/           # Out-of-band Intent Resolution engine
├── sat/                # SAT Validation & Lifecycle Management
├── safety-gates/       # MAMA deterministic policy engine (Funding, Safety, Value)
├── crypto/             # Ed25519, HKDF, Noise IK cryptographic wrappers
├── telemetry/          # Prometheus exporters and performance metrics
├── sba/                # 3GPP SBA integration proxy and middleware
├── sdk/                # Python, Rust, and C++ Client SDKs for autonomous agents
├── experiments/        # SDR Validation, GNU Radio blocks, hardware interfacing
├── tests/              # E2E integration, fuzzing, and cryptographic test vectors
├── docs/               # API specs, sequence diagrams, threat models
└── deployment/         # Dockerfiles, Kubernetes manifests, Helm charts
```

---

## PHASE 3 — IMPLEMENTATION ROADMAP

### Phase 1: Protocol Core
- Formalize KNK (Knowledge Network Key) and AOP (Agent Operation Protocol) structures using Protobuf/Flatbuffers.
- Implement zero-copy parsers in Rust/C++.

### Phase 2: NHP Handshake
- Implement the Fail-Closed 5-state machine.
- Integrate eBPF/XDP hooks to drop unverified packets before kernel TCP/IP stack allocation.

### Phase 3: AgentDNS
- Develop the intent-based routing table.
- Implement UDP/TCP DNS-like query resolution for autonomous agents.

### Phase 4: SAT Validation
- Implement secure token issuance, verification, and revocation logic.
- Integrate temporal bounds checking and skew tolerance.

### Phase 5: Safety Gate Engine
- Port the MAMA math ($Score_{safety} = w_1(1-EDNS) + w_2(CEI)$) into a high-performance evaluation loop in Rust.
- Implement real-time parameter tuning APIs.

### Phase 6: Telemetry Integration
- Embed Prometheus metrics for CPU/RAM footprint, latency, and signature validation times.
- Build Grafana dashboards for "Digital Sovereignty Immunity" visualization.

### Phase 7: 3GPP SBA Integration
- Develop an Envoy-based or custom Rust-based proxy to sit in front of AMF/SMF functions.

### Phase 8: Experimental Validation
- Hardware loop integration with SDRs for FR3 validation.

---

## PHASE 4 — FR3 SDR VALIDATION

### Target Hardware Stack
- **USRP X440**: Broad spectrum RF transceiver.
- **TMYTEK UD Box 0630**: mmWave Up/Down Converter for 5G FR3 bands.
- **Antenna**: 4T4R MIMO architecture.
- **Software**: GNU Radio, ZTCPP Python/C++ SDKs.

### Design Specifications
- **APIs**: An async Python/C++ HAL that maps ZTCPP "Intents" directly to SDR beamforming weights and gain control parameters.
- **Interfaces**: ZeroMQ/gRPC bridging between the ZTCPP daemon and GNU Radio out-of-tree (OOT) blocks.
- **Telemetry Collection**: Capture EVM (Error Vector Magnitude), SNR, and latency from the TMYTEK box correlated with ZTCPP handshakes.

---

## PHASE 5 — TEST SCENARIOS

### Scenario A: Autonomous Beamforming Authorization
- **Objective**: Validate that a drone agent can securely request and adjust beamforming arrays.
- **Workflow**: Agent -> AgentDNS (Resolution) -> NHP (AbC Verification) -> MAMA (Safety Check) -> SDR HAL.
- **Metrics**: End-to-end latency, Cryptographic verification time.
- **Expected Results**: Complete handshake < 2ms, authorized physical beam steer.

### Scenario B: AgentDNS Resolution
- **Objective**: Verify topological abstraction.
- **Workflow**: Agent queries `intent=monitor_amf`, AgentDNS returns dynamic cryptographic token and routing endpoint.
- **Expected Results**: Resolution without exposing internal IP architecture.

### Scenario C: SAT Validation
- **Objective**: Resilience against Token Replay and Skew.
- **Workflow**: Inject previously captured valid SAT tokens into the AbC edge.
- **Expected Results**: Packets dropped immediately at the edge due to monotonic nonce collision.

### Scenario D: EDNS-triggered Revocation
- **Objective**: Validate the Safety Gate under network saturation.
- **Workflow**: Artificially increase Expected Demand Not Served (EDNS) telemetry, then initiate new agent requests.
- **Expected Results**: MAMA gate dynamically rejects requests ($Score_{safety} < 0.85$) to preserve core stability.

### Scenario E: Autonomous Remediation
- **Objective**: Validate fast-tracking of high-value operations.
- **Workflow**: Agent requests `intent=isolate_threat` with a high Capability Effectiveness Index (CEI).
- **Expected Results**: MAMA gate overrides lower priority traffic, granting instant access.

### Scenario F: Zero-Trust SBA Invocation
- **Objective**: Lateral movement mitigation within 5G Core.
- **Workflow**: Simulated compromised NF attempts unauthorized API call to another NF without a valid SAT.
- **Expected Results**: Connection dropped by SBA sidecar proxy before HTTP parsing.

---

## PHASE 6 — SECURITY & CRYPTOGRAPHY

### Primitives
- **Handshake Framework**: Noise IK pattern for mutual authentication and zero round-trip time (0-RTT) resumption.
- **Signatures**: Ed25519 for deterministic, high-speed verification at the edge.
- **Key Derivation**: HKDF (HMAC-based Extract-and-Expand Key Derivation Function).
- **Symmetric Encryption**: ChaCha20-Poly1305 (AEAD).

### Threat Mitigations
- **Replay Attacks**: Thwarted by strictly monotonically increasing nonces embedded in the pre-connection signature.
- **Downgrade Attacks**: Eliminated by removing cipher-suite negotiation; parameters are strictly hardcoded.
- **Token Abuse**: Addressed via short-lived expiration bounds (e.g., 60 seconds) and strict API audience binding.
- **State-machine Abuse**: Prevented by the AbC Fail-Closed 5-state machine. No TCP/TLS socket memory is allocated until the Ed25519 JWS is fully verified in a stateless context (or via XDP).

---

## PHASE 7 — DELIVERABLES CHECKLIST

1. [x] **Repository Roadmap**: Outlined in Phase 3.
2. [x] **Directory Tree**: Defined in Phase 2.
3. [x] **Module Specifications**: High-level specs integrated into architecture design.
4. [ ] **API Specifications**: (Pending) OpenAPI YAML specs for NHP and AgentDNS.
5. [ ] **Sequence Diagrams**: (Pending) MermaidJS diagrams for AbC Handshake.
6. [ ] **Class Diagrams**: (Pending) MermaidJS diagrams for MAMA Safety Gates.
7. [x] **Implementation Priorities**: Phase 1 (Core) -> Phase 2 (NHP) -> Phase 5 (MAMA).
8. [x] **CI/CD Recommendations**: GitHub Actions with Valgrind/Miri for zero-allocation verification.
9. [x] **Docker Strategy**: Distroless multi-stage Rust/C++ images for minimal attack surface.
10. [x] **Testing Strategy**: End-to-end hardware loop testing (Phase 4/5) and unit test matrices.
